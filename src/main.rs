extern crate libc;
extern crate nix;
extern crate mio;

use std::mem;
use std::os::unix::prelude::AsRawFd;

use nix::sys::socket::{CmsgSpace, recvmsg, MsgFlags, ControlMessage};
use nix::sys::uio::IoVec;

#[allow(dead_code)]
#[repr(C)]
struct BlSockaddr {
    sa_family: u16,
    hci_device: u16,
    channel: u16
}

impl BlSockaddr {
    pub fn new(hci_device: u16) -> BlSockaddr {
        BlSockaddr {
            sa_family: libc::AF_BLUETOOTH as u16,
            hci_device,
            channel: 0,
        }
    }
}


struct BluetoothSocket {
    hci_device: u16,
    io: mio::Io,
}

const BTPROTO_HCI: i32 = 1;
const SOL_HCI: i32 = 0;
const HCI_DATA_DIR: i32 = 1;
const HCI_FILTER: i32 = 2;
const HCI_TIME_STAMP: i32 = 3;

#[repr(C)]
struct HciFilter {
    pub type_mask: u32,
    pub event_mask: [u32; 2],
    pub opcode: u16,
}

fn dump<T>(d: &T) {
    let view = &d as *const _ as *const u8;
    for i in 0..(mem::size_of_val(&view) as isize) {
        print!("{:02x} ", unsafe { *view.offset(i) });
    }
    println!("");
}

impl BluetoothSocket {
    pub fn new(hci_device: u16) -> nix::Result<BluetoothSocket> {
        let fd = unsafe { libc::socket(libc::AF_BLUETOOTH, libc::SOCK_RAW, BTPROTO_HCI) };
        if fd < 0 {
            return Err(nix::Error::last());
        }

        let opt = 1;
        if unsafe {
            libc::setsockopt(fd,
                             SOL_HCI, HCI_DATA_DIR,
                             &opt as *const _ as *const libc::c_void,
                             mem::size_of_val(&opt) as u32)
        } != 0 {
            return Err(nix::Error::last());
        }

        BluetoothSocket::set_up_filter(fd)?;

        let opt = 1;
        if unsafe {
            libc::setsockopt(fd,
                             SOL_HCI,
                             HCI_TIME_STAMP,
                             &opt as *const _ as *const libc::c_void,
                             mem::size_of_val(&opt) as u32)
        } != 0 {
            return Err(nix::Error::last());
        }

        Ok(BluetoothSocket {
            hci_device,
            io: mio::Io::from_raw_fd(fd),
        })
    }

    fn set_up_filter(fd: i32) -> nix::Result<()> {
        let filter = HciFilter {
            type_mask: 0xFFFFFFFF,
            event_mask: [0xFFFFFFFF, 0xFFFFFFFF],
            opcode: 0,
        };
        if unsafe {
            libc::setsockopt(fd,
                             SOL_HCI,
                             HCI_FILTER,
                             &filter as *const _ as *const libc::c_void,
                             mem::size_of_val(&filter) as u32)
        } < 0 {
            return Err(nix::Error::last());
        } else {
            Ok(())
        }
    }

    pub fn bind(&self) -> nix::Result<()> {
        let address = BlSockaddr::new(self.hci_device);
        let result = unsafe {
            libc::bind(self.io.as_raw_fd(),
                       &address as *const _ as *const libc::sockaddr,
                       mem::size_of::<BlSockaddr>() as u32)
        };
        if result == 0 {
            Ok(())
        } else {
            Err(nix::Error::last())
        }
    }

    pub fn poll(&self) {
        let flags = nix::poll::POLLIN;
        let pfd = nix::poll::PollFd::new(self.io.as_raw_fd(), flags);
        nix::poll::poll(&mut [pfd], -1).unwrap();
        let revents = pfd.revents().unwrap().bits();
        if revents != 0 {
            println!("poll error: {}", revents);
            return;
        }
    }

    pub fn recvmsg(&self) -> Vec<u8> {
        let flags = MsgFlags::empty();
        let mut buf = [0u8; 100];
        let iov = [IoVec::from_mut_slice(&mut buf[..])];
        let mut cmsgspace: CmsgSpace<[[u8; 30]; 2]> = CmsgSpace::new();
        let recv_msg = recvmsg(self.io.as_raw_fd(), &iov, Some(&mut cmsgspace), flags);
        let recv_msg = recv_msg.unwrap();

//        for cmsg in recv_msg.cmsgs() {
            //            dump(&cmsg);
            //            if let ControlMessage::Unknown(fd) = cmsg {
            //                                panic!("unexpected cmsg");
            //            } else {
            //                                panic!("unexpected cmsg");
            //            }
//        }

        iov[0].as_slice()[..recv_msg.bytes].to_vec()
    }
}

struct BleAddress {
    address: [u8; 6],
}

impl std::fmt::Debug for BleAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "BleAddress {{ {:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X} }}",
               self.address[0], self.address[1], self.address[2],
               self.address[3], self.address[4], self.address[5])
    }
}

impl BleAddress {
    pub fn from_bytes(bytes: [u8; 6]) -> BleAddress {
        if bytes.len() != 6 {
            panic!("Unable to create BleAddress from bytes {:?}", bytes.to_vec());
        }
        BleAddress {
            address: bytes,
        }
    }
}

#[derive(Debug)]
enum Direction {
    In,
    Out
}

#[derive(Debug)]
struct BlePacket {
    // TODO: add timestamp, get it somehow from ControlMessage
    pub rssi: i8,
    pub address: BleAddress,
    pub data: Vec<u8>,
    pub size: usize,
    pub direction: Direction,
}

impl BlePacket {
    pub fn from_bytes(bytes: Vec<u8>) -> Result<BlePacket, String> {
        if bytes.len() < 14 {
            return Err("To short data to analyze".to_string());
        }
        let size = bytes[13] as usize;
        if bytes.len() != 14 + size + 1 {
            // Packet starts at 14, last byte is rssi
            return Err("Incorrect size".to_string());
        }
        if bytes[0] != 0x04 || bytes[1] != 0x3e || bytes[3] != 0x02 || bytes[4] != 0x01 {
            return Err("Not Ble packet".to_string());
        }
        let mut address: [u8; 6] = [0; 6];
        address.clone_from_slice(&bytes[7..13]);

        let packet = BlePacket {
            rssi: bytes[bytes.len() - 1] as i8,
            address: BleAddress::from_bytes(address),
            size,
            data: bytes[14..].to_vec(),
            // TODO: Get it somehow from ControlMessage
            direction: Direction::In,
        };

        Ok(packet)
    }
}

fn main() {
    let socket = BluetoothSocket::new(0).unwrap();
    socket.bind().expect("Cannot bind to socket");

    loop {
        socket.poll();
        let data = socket.recvmsg();
        let packet = match BlePacket::from_bytes(data) {
            Ok(p) => { p }
            Err(_) => { continue }
        };
        println!("packet: {:?}", packet);
    }
}
