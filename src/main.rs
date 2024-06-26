use std::{cell::OnceCell, collections::{hash_map::Entry, HashMap}, env, fs::File, io::{Read, Result}};
mod perfetto;
use perfetto::{ftrace_event::Event, trace_packet, track_event, Trace, TracePacketDefaults};
use prost::Message;
use perfetto::trace_packet::Data::*;

use crate::perfetto::track_event::NameField;

struct Track {
    tid: i32,
    has_parent: bool,
    name: OnceCell<String>,
    stack: Vec<(u64, String)>
}

impl Track {
    fn output_marker(&self, start: u64, end: u64, value: &str) {
        let name =  self.name.get_or_init(|| value.split_whitespace().next().unwrap().to_owned());
        println!("{} {} {} {} {}", self.tid, name, start, end, value);
    }
}
fn main() {

    // read in the trace to a fec
    let mut file = File::open(env::args().nth(1).unwrap()).unwrap();
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer).unwrap();
    let trace = Trace::decode(buffer.as_slice()).unwrap();
    //dbg!(&trace);

    let mut chrome_time = 0;
    let mut current_chrome_time = 0;
    let mut boot_to_mono = 0;
    let mut ftrace_thread_state = HashMap::new();
    let mut tracks: HashMap<u64, Track> = HashMap::new();
    let mut ftrace_events = Vec::new();
    let mut event_names = HashMap::new();
    let mut default_track_uuid = 0;
    let mut first = true;
    let default_trace_clock_id = 6;
    let mut default_timestamp_clock_id = None;

    for packet in trace.packet {
        if let Some(trace_packet_defaults) = packet.trace_packet_defaults {
            if let Some(timestamp_clock_id) = trace_packet_defaults.timestamp_clock_id {
                assert_eq!(timestamp_clock_id, 64);
                default_timestamp_clock_id = Some(timestamp_clock_id);
                eprintln!("timestamp_clock_id: {:?}", timestamp_clock_id);
            }
            if let Some(track_event_defaults) = trace_packet_defaults.track_event_defaults {
                if let Some(track_uuid) = track_event_defaults.track_uuid {
                    default_track_uuid = track_uuid;
                }
            }
        }
        if let Some(data) = packet.data {
            if let Some(timestamp) = packet.timestamp {
                let clock_id = packet.timestamp_clock_id.or(default_timestamp_clock_id).unwrap_or(default_trace_clock_id);
                if clock_id == 64 {
                    current_chrome_time += timestamp;
                }
            }
            match data {
                ClockSnapshot(clock_snapshot) => {
                    let mut boot_time = 0;
                    let mut mono_time = 0; 
                    for clock in clock_snapshot.clocks {
                        match clock.clock_id.unwrap() {
                            6 => boot_time = clock.timestamp.unwrap(),
                            3 => mono_time = clock.timestamp.unwrap(),
                            64 => {
                                assert!(clock.is_incremental());
                                chrome_time = clock.timestamp.unwrap();
                                if chrome_time == boot_time {
                                    chrome_time = chrome_time - boot_to_mono;
                                }
                                current_chrome_time = chrome_time;
                            },
                            _ => (),
                        }
                    }
                    // only compute the difference if we have both
                    if boot_time != 0 && mono_time != 0 {
                        if boot_time < mono_time {
                            // boot_time sometimes shows up as less than mono_time
                            // this might be because we measure it first. Make sure
                            // the difference between them is small and just '0'
                            // as our conversion difference.
                            assert!((mono_time - boot_time) < 1000);
                            boot_to_mono = 0;   
                        } else {
                            boot_to_mono = boot_time - mono_time;
                        }
                    }
                },
                FtraceEvents(ftrace_event_bundle) => {
                    for e in ftrace_event_bundle.event {
                        //let timestamp = e.timestamp.unwrap();
                        //let pid = e.pid.unwrap();
                        //dbg!(&e);
                        let timestamp = e.timestamp.unwrap();
                        ftrace_events.push((e, timestamp));
                    }
                },
                TrackDescriptor(track_descriptor) => {
                    eprintln!("{:?}", track_descriptor);
                    let uuid = track_descriptor.uuid.unwrap();
                    let mut tid = 0;

                    // start with the parent track tid if it exists
                    if let Some(parent_uuid) = track_descriptor.parent_uuid {
                        if let Some(parent) = tracks.get(&parent_uuid) {
                            tid = parent.tid;
                        }
                    }
                    let mut name = OnceCell::new();
                    if let Some(process) = track_descriptor.process {
                        tid = process.pid.unwrap();
                        name.set("Process".to_owned());

                    }
                    if let Some(thread) = track_descriptor.thread {
                        tid = thread.tid.unwrap();
                        name.set("Thread".to_owned());
                    }
                    // Perfetto seems to use the event name of the first event as the track name
                    tracks.insert(uuid, Track { tid, name, has_parent: track_descriptor.parent_uuid.is_some(), stack: Vec::new()});

                },
                TrackEvent(track_event) => 'track_event: {
                    let track_uuid = if let Some(uuid) = track_event.track_uuid {
                        if uuid == 0 {
                            // if the track_uuid is 0, then we'll put this event in the track that matches trusted_pid
                            if let Some(trusted_pid) = packet.trusted_pid {
                                // find the track that corresponds to the trusted_pid and has no parent
                                if let Some((&uuid, _)) = tracks.iter().find(|(_, track)| track.tid == trusted_pid && !track.has_parent) {
                                    uuid
                                } else {
                                    panic!("missing track for trusted_pid {}", trusted_pid);
                                    break 'track_event;
                                }
                            } else {
                                panic!("no track");
                                // otherwise drop the event
                                break 'track_event;
                            }
                        } else {
                             uuid
                        }
                    } else {
                        default_track_uuid
                    };

                    if let Some(interned_data) = packet.interned_data {
                        for name in interned_data.event_names {
                            event_names.insert(name.iid(), name.name().to_owned());
                        }
                    }
                    if let Some(timestamp) = packet.timestamp {
                        // if the timestamp_clock_id is 64, then we'll use the incremental current_chrome_time
                        let clock_id = packet.timestamp_clock_id.or(default_timestamp_clock_id).unwrap_or(default_trace_clock_id);
                        let timestamp = if clock_id == 64 {
                            current_chrome_time
                        } else if clock_id == 3 {
                            timestamp
                        } else {
                            panic!("unexpected clock_id {}", clock_id);
                        };
                        let name = match &track_event.name_field {
                            Some(NameField::NameIid(iid)) => Some(event_names[iid].as_str()),
                            Some(NameField::Name(name)) => Some(name.as_str()),
                            None => None,
                        };
                        let track = tracks.get_mut(&track_uuid).unwrap();
                        match track_event.r#type() {
                            track_event::Type::SliceBegin => {
                                // initialize the track name if it hasn't already been set
                                track.name.get_or_init(|| name.unwrap().split_whitespace().next().unwrap().to_owned());

                                track.stack.push((timestamp, name.unwrap().to_owned()));
                                //println!("{} Begin {:?} {:?}", track.tid, current_chrome_time, name.unwrap());

                            },
                            track_event::Type::Instant => {
                                track.output_marker(timestamp, timestamp, name.unwrap());
                            },
                            track_event::Type::SliceEnd => {
                                if let Some((start_time, name)) = track.stack.pop() {
                                    track.output_marker(start_time, timestamp, &name);
                                } else {
                                    eprintln!("missing start")
                                }
                            }
                            track_event::Type::Unspecified => {
                                if let Some(legacy_event) = track_event.legacy_event {
                                    match legacy_event.phase.unwrap() as u8 as char {
                                        'b' => {
                                            track.stack.push((timestamp, name.unwrap().to_owned()));
                                        },
                                        'e' => {
                                            if let Some((start_time, name)) = track.stack.pop() {
                                                track.output_marker(start_time, timestamp, &name);
                                            } else {
                                                eprintln!("missing start")
                                            }
                                        },
                                        'n' => {
                                            track.output_marker(timestamp, timestamp, name.unwrap());
                                        }
                                        _ => (),
                                    }
                                }
                            }
                            _ => (),
                        }
                    }

                    //println!("{:?}", track_event);
                },
                _ => (),
            }
        }
    }
    ftrace_events.sort_by_key(|x| x.1);
    for (e, timestamp) in &ftrace_events {
        let timestamp = *timestamp;
        let pid = e.pid.unwrap();
        match e.event.as_ref().unwrap() {
            Event::Print(ftrace_print) => {
                
                let buf = ftrace_print.buf.as_ref().unwrap();
                //println!("{}", timestamp);
                // See ParseSystraceTracePoint in perfetto for how to parse these things

                // drop new line at the end
                let buf = &buf[..buf.len()-1];
                // B|1356|prepareSurfaces
                let mut pieces = buf.split('|');

                let phase = pieces.nth(0).unwrap().chars().nth(0).unwrap();
                let tgid: i32 = pieces.nth(0).unwrap().parse().unwrap();

                //println!("{} {} {}", pid, timestamp, buf);

                match ftrace_thread_state.entry(pid) {
                    Entry::Occupied(o) => {
                        let state: &mut Vec<(u64, char, &str)> = o.into_mut();
                        match phase {
                            'B' => {
                                let msg = pieces.nth(0).unwrap();
                                state.push((timestamp, phase, msg));
                            },
                            'E' => {
                                if let Some((start, _, msg)) = state.pop() {
                                    println!("{} ftrace {} {} {}", pid, start - boot_to_mono, timestamp - boot_to_mono, msg);
                                } else {
                                    eprintln!("missing start for {}", timestamp)
                                }
                            },
                            _ => (),
                        }
                    },
                    Entry::Vacant(v) => {
                        v.insert(vec![(timestamp, phase, buf)]);
                    }
                }

                //println!("{}: {} -> {} {}", timestamp - boot_to_mono, buf, phase, tgid);
            },
            _ => (),
        }
        
    }
}  

/*fn main() -> Result<()> {
    prost_build::compile_protos(&["../../src/perfetto/protos/perfetto/trace/perfetto_trace.proto"], &["../../src/perfetto/protos/perfetto/trace/"])?;
    Ok(())
}*/
