use std::{collections::{hash_map::Entry, HashMap}, env, fs::File, io::{Read, Result}};
mod perfetto;
use perfetto::{ftrace_event::Event, trace_packet, track_event, Trace, TracePacketDefaults};
use prost::Message;
use perfetto::trace_packet::Data::*;

use crate::perfetto::track_event::NameField;

struct Track {
    tid: i32,
    stack: Vec<(u64, String)>
}
fn main() {

    // read in the trace to a fec
    let mut file = File::open(env::args().nth(1).unwrap()).unwrap();
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer).unwrap();
    let trace = Trace::decode(buffer.as_slice()).unwrap();
    //dbg!(&trace);
    let mut boot_time = 0;
    let mut mono_time = 0;
    let mut chrome_time = 0;
    let mut current_chrome_time = 0;
    let mut boot_to_mono = 0;
    let mut ftrace_thread_state = HashMap::new();
    let mut tracks = HashMap::new();
    let mut ftrace_events = Vec::new();
    let mut event_names = HashMap::new();
    let mut track_uuid = 0;
    
    for packet in trace.packet {
        if let Some(trace_packet_defaults) = packet.trace_packet_defaults {
            if let Some(timestamp_clock_id) = trace_packet_defaults.timestamp_clock_id {
                assert_eq!(timestamp_clock_id, 64);
                eprintln!("timestamp_clock_id: {:?}", timestamp_clock_id);
            }
            if let Some(track_event_defaults) = trace_packet_defaults.track_event_defaults {
                if let Some(track_uuid_) = track_event_defaults.track_uuid {
                    track_uuid = track_uuid_;
                }
            }
        }
        if let Some(data) = packet.data {
            if let Some(timestamp) = packet.timestamp {
                current_chrome_time += timestamp;
            }
            match data {
                ClockSnapshot(clock_snapshot) => {
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
                        boot_to_mono = boot_time - mono_time;
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
                    if let Some(process) = track_descriptor.process {
                        tid = process.pid.unwrap();
                    }
                    if let Some(thread) = track_descriptor.thread {
                        tid = thread.tid.unwrap();
                    }
                    tracks.insert(uuid, Track { tid, stack: Vec::new()});

                },
                TrackEvent(track_event) => {
                    if let Some(interned_data) = packet.interned_data {
                        for name in interned_data.event_names {
                            event_names.insert(name.iid(), name.name().to_owned());
                        }
                    }
                    if let Some(timestamp) = packet.timestamp {
                        let name = match &track_event.name_field {
                            Some(NameField::NameIid(iid)) => Some(event_names[iid].as_str()),
                            Some(NameField::Name(name)) => Some(name.as_str()),
                            None => None,
                        };
                        let track = tracks.get_mut(&track_uuid).unwrap();
                        match track_event.r#type() {
                            track_event::Type::SliceBegin => {
                                track.stack.push((current_chrome_time, name.unwrap().to_owned()));
                                //println!("{} Begin {:?} {:?}", track.tid, current_chrome_time, name.unwrap());

                            },
                            track_event::Type::Instant => {
                                println!("{} {:?} {} {}", track.tid, current_chrome_time, current_chrome_time, name.unwrap());
                            },
                            track_event::Type::SliceEnd => {
                                if let Some((start_time, name)) = track.stack.pop() {
                                    println!("{} {:?} {} {}", track.tid, start_time, current_chrome_time, name);
                                } else {
                                    eprintln!("missing start")
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
                                    println!("{} {} {} {}", pid, start - boot_to_mono, timestamp - boot_to_mono, msg);
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
