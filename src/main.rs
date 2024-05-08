use std::{collections::{hash_map::Entry, HashMap}, env, fs::File, io::{Read, Result}};
mod perfetto;
use perfetto::{ftrace_event::Event, Trace};
use prost::Message;
use perfetto::trace_packet::Data::*;
fn main() {

    // read in the trace to a fec
    let mut file = File::open(env::args().nth(1).unwrap()).unwrap();
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer).unwrap();
    let trace = Trace::decode(buffer.as_slice()).unwrap();
    //dbg!(&trace);
    let mut boot_time = 0;
    let mut mono_time = 0;
    let mut boot_to_mono = 0;
    let mut thread_state = HashMap::new();
    let mut ftrace_events = Vec::new();
    for packet in trace.packet {
        if let Some(data) = packet.data {
            match data {
                ClockSnapshot(clock_snapshot) => {
                    for clock in clock_snapshot.clocks {
                        match clock.clock_id.unwrap() {
                            6 => boot_time = clock.timestamp.unwrap(),
                            3 => mono_time = clock.timestamp.unwrap(),
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

                match thread_state.entry(pid) {
                    Entry::Occupied(o) => {
                        let state: &mut Vec<(u64, char, &str)> = o.into_mut();
                        match phase {
                            'B' => {
                                let msg = pieces.nth(0).unwrap();
                                state.push((timestamp, phase, msg));
                            },
                            'E' => {
                                let (start, _, msg) = state.pop().unwrap();
                                println!("{} {} {} {}", pid, start - boot_to_mono, timestamp - boot_to_mono, msg);
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
