pub mod compress;
pub mod platform;
pub mod protos;
pub use bytes;
use config::Config;
pub use futures;
pub use protobuf;
pub use protos::message as message_proto;
pub use protos::rendezvous as rendezvous_proto;
use std::{
    fs::File,
    io::{self, BufRead},
    net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4},
    path::Path,
    time::{self, SystemTime, UNIX_EPOCH},
};
pub use tokio;
pub use tokio_util;
pub mod socket_client;
pub mod tcp;
pub mod udp;
pub use env_logger;
pub use log;
pub mod bytes_codec;
// #[cfg(feature = "quic")]
// pub mod quic;
pub use anyhow::{self, bail};
pub use futures_util;
pub mod config;
pub mod fs;
pub use lazy_static;
#[cfg(not(any(target_os = "android", target_os = "ios")))]
pub use mac_address;
pub use rand;
pub use regex;
pub use sodiumoxide;
pub use tokio_socks;
pub use tokio_socks::IntoTargetAddr;
pub use tokio_socks::TargetAddr;
pub mod password_security;
pub use chrono;
pub use directories_next;
pub mod keyboard;

// #[cfg(feature = "quic")]
// pub type Stream = quic::Connection;
// #[cfg(not(feature = "quic"))]
pub type Stream = tcp::FramedStream;

#[inline]
pub async fn sleep(sec: f32) {
    tokio::time::sleep(time::Duration::from_secs_f32(sec)).await;
}

#[macro_export]
macro_rules! allow_err {
    ($e:expr) => {
        if let Err(err) = $e {
            log::debug!(
                "{:?}, {}:{}:{}:{}",
                err,
                module_path!(),
                file!(),
                line!(),
                column!()
            );
        } else {
        }
    };

    ($e:expr, $($arg:tt)*) => {
        if let Err(err) = $e {
            log::debug!(
                "{:?}, {}, {}:{}:{}:{}",
                err,
                format_args!($($arg)*),
                module_path!(),
                file!(),
                line!(),
                column!()
            );
        } else {
        }
    };
}

#[inline]
pub fn timeout<T: std::future::Future>(ms: u64, future: T) -> tokio::time::Timeout<T> {
    tokio::time::timeout(std::time::Duration::from_millis(ms), future)
}

pub type ResultType<F, E = anyhow::Error> = anyhow::Result<F, E>;

/// 对 Socket 地址进行编码和解码
///
/// Certain router and firewalls scan the packet and if they
/// find an IP address belonging to their pool that they use to do the NAT mapping/translation, so here we mangle the ip address
pub struct AddrMangle();

#[inline]
/// 将 IPv6 地址转换为 IPv4 地址
/// 如果提供的 Socket 地址是 IPv6 地址，并且不是回环地址，将其转换为 IPv4 地址
/// 如果成功转化则返回 ipv4 socket 地址，否则原样返回
pub fn try_into_v4(addr: SocketAddr) -> SocketAddr {
    match addr {
        SocketAddr::V6(v6) if !addr.ip().is_loopback() => {
            if let Some(v4) = v6.ip().to_ipv4() {
                SocketAddr::new(IpAddr::V4(v4), addr.port())
            } else {
                addr
            }
        }
        _ => addr,
    }
}

impl AddrMangle {
    /// 对socket进行 编码成字节数组
    ///
    /// - 如果提供的 Socket 地址是 IPv4 地址，将其进行特定的编码处理。
    ///   - 根据当前时间生成一个时间戳 tm，并转换为 u128 类型。
    ///   - 将 IPv4 地址和 tm 进行位运算，并生成唯一的 u128 值 v。
    ///   - 将 v 转换为字节数组，并去除末尾的填充零字节。
    /// - 如果提供的 Socket 地址是 IPv6 地址，将 IPv6 地址的字节表示转换为字节数组，然后追加端口号的字节表示。
    pub fn encode(addr: SocketAddr) -> Vec<u8> {
        // not work with [:1]:<port>
        let addr = try_into_v4(addr);
        match addr {
            SocketAddr::V4(addr_v4) => {
                // [ip+tm][tm][port+(tm低16位)]
                let tm: u128 = (SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_micros() as u32) as u128;
                let ip = u32::from_le_bytes(addr_v4.ip().octets()) as u128; // 字节数组转换为 u32 类型的整数 -> u128
                let port = addr.port() as u128;
                // ipv4 32位， ip+tm(唯一标识,区分连接，高位) 达到 v 的最高位(<<49)
                let v = ((ip + tm) << 49) | (tm << 17) | (port + (tm & 0xFFFF/* tm的低16位 */));
                let bytes = v.to_le_bytes();
                let mut n_padding = 0;
                for i in bytes.iter().rev() {
                    if i == &0u8 {
                        n_padding += 1;
                    } else {
                        break;
                    }
                }
                bytes[..(16 - n_padding)].to_vec()
            }
            SocketAddr::V6(addr_v6) => {
                let mut x = addr_v6.ip().octets().to_vec();
                let port: [u8; 2] = addr_v6.port().to_le_bytes();
                x.push(port[0]);
                x.push(port[1]);
                x
            }
        }
    }

    /// 对字节数组 解码成socket
    ///
    /// - 如果提供的字节数组的长度大于16，表示该字节数组可能是 IPv6 地址的编码结果，进行如下处理：
    ///   - 检查字节数组长度是否正确，如果不正确，则返回一个任意监听地址的配置。
    ///   - 从字节数组中提取出端口号，并转换为 u16 类型。
    ///   - 从字节数组中提取出 IPv6 地址的字节表示，并转换为 std::net::Ipv6Addr 类型。
    ///   - 返回由 IPv6 地址和端口号构成的 Socket 地址。
    /// - 如果提供的字节数组的长度小于等于16，表示该字节数组是 IPv4 地址的编码结果，进行如下处理：
    ///   - 创建一个大小为16的零填充字节数组 padded。
    ///   - 将字节数组复制到 padded 中。
    ///   - 将 padded 转换为 u128 类型。
    ///   - 通过位运算和字节转换，从 u128 值中提取 IPv4 地址和端口号。
    ///   - 返回由 IPv4 地址和端口号构成的 Socket 地址。
    pub fn decode(bytes: &[u8]) -> SocketAddr {
        use std::convert::TryInto;

        if bytes.len() > 16 {
            if bytes.len() != 18 {
                return Config::get_any_listen_addr(false);
            }
            let tmp: [u8; 2] = bytes[16..].try_into().unwrap();
            let port = u16::from_le_bytes(tmp);
            let tmp: [u8; 16] = bytes[..16].try_into().unwrap();
            let ip = std::net::Ipv6Addr::from(tmp);
            return SocketAddr::new(IpAddr::V6(ip), port);
        }
        let mut padded = [0u8; 16];
        padded[..bytes.len()].copy_from_slice(bytes);
        let number = u128::from_le_bytes(padded);
        let tm = (number >> 17) & (u32::max_value() as u128);
        let ip = (((number >> 49) - tm) as u32).to_le_bytes();
        let port = (number & 0xFFFFFF) - (tm & 0xFFFF);
        SocketAddr::V4(SocketAddrV4::new(
            Ipv4Addr::new(ip[0], ip[1], ip[2], ip[3]),
            port as u16,
        ))
    }
}

// software_url
pub fn get_version_from_url(url: &str) -> String {
    let n = url.chars().count();
    let a = url.chars().rev().position(|x| x == '-');
    if let Some(a) = a {
        let b = url.chars().rev().position(|x| x == '.');
        if let Some(b) = b {
            if a > b {
                if url
                    .chars()
                    .skip(n - b)
                    .collect::<String>()
                    .parse::<i32>()
                    .is_ok()
                {
                    return url.chars().skip(n - a).collect();
                } else {
                    return url.chars().skip(n - a).take(a - b - 1).collect();
                }
            } else {
                return url.chars().skip(n - a).collect();
            }
        }
    }
    "".to_owned()
}

pub fn gen_version() {
    println!("cargo:rerun-if-changed=Cargo.toml");
    use std::io::prelude::*;
    let mut file = File::create("./src/version.rs").unwrap();
    for line in read_lines("Cargo.toml").unwrap().flatten() {
        let ab: Vec<&str> = line.split('=').map(|x| x.trim()).collect();
        if ab.len() == 2 && ab[0] == "version" {
            file.write_all(format!("pub const VERSION: &str = {};\n", ab[1]).as_bytes())
                .ok();
            break;
        }
    }
    // generate build date
    let build_date = format!("{}", chrono::Local::now().format("%Y-%m-%d %H:%M"));
    file.write_all(
        format!("#[allow(dead_code)]\npub const BUILD_DATE: &str = \"{build_date}\";\n").as_bytes(),
    )
    .ok();
    file.sync_all().ok();
}

fn read_lines<P>(filename: P) -> io::Result<io::Lines<io::BufReader<File>>>
where
    P: AsRef<Path>,
{
    let file = File::open(filename)?;
    Ok(io::BufReader::new(file).lines())
}

pub fn is_valid_custom_id(id: &str) -> bool {
    regex::Regex::new(r"^[a-zA-Z]\w{5,15}$")
        .unwrap()
        .is_match(id)
}

pub fn get_version_number(v: &str) -> i64 {
    let mut n = 0;
    for x in v.split('.') {
        n = n * 1000 + x.parse::<i64>().unwrap_or(0);
    }
    n
}

pub fn get_modified_time(path: &std::path::Path) -> SystemTime {
    std::fs::metadata(path)
        .map(|m| m.modified().unwrap_or(UNIX_EPOCH))
        .unwrap_or(UNIX_EPOCH)
}

pub fn get_created_time(path: &std::path::Path) -> SystemTime {
    std::fs::metadata(path)
        .map(|m| m.created().unwrap_or(UNIX_EPOCH))
        .unwrap_or(UNIX_EPOCH)
}

pub fn get_exe_time() -> SystemTime {
    std::env::current_exe().map_or(UNIX_EPOCH, |path| {
        let m = get_modified_time(&path);
        let c = get_created_time(&path);
        if m > c {
            m
        } else {
            c
        }
    })
}

pub fn get_uuid() -> Vec<u8> {
    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    if let Ok(id) = machine_uid::get() {
        return id.into();
    }
    Config::get_key_pair().1
}

#[inline]
pub fn get_time() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0) as _
}

#[inline]
pub fn is_ipv4_str(id: &str) -> bool {
    regex::Regex::new(r"^\d+\.\d+\.\d+\.\d+(:\d+)?$")
        .unwrap()
        .is_match(id)
}

#[inline]
pub fn is_ipv6_str(id: &str) -> bool {
    regex::Regex::new(r"^((([a-fA-F0-9]{1,4}:{1,2})+[a-fA-F0-9]{1,4})|(\[([a-fA-F0-9]{1,4}:{1,2})+[a-fA-F0-9]{1,4}\]:\d+))$")
        .unwrap()
        .is_match(id)
}

#[inline]
pub fn is_ip_str(id: &str) -> bool {
    is_ipv4_str(id) || is_ipv6_str(id)
}

#[inline]
pub fn is_domain_port_str(id: &str) -> bool {
    // modified regex for RFC1123 hostname. check https://stackoverflow.com/a/106223 for original version for hostname.
    // according to [TLD List](https://data.iana.org/TLD/tlds-alpha-by-domain.txt) version 2023011700,
    // there is no digits in TLD, and length is 2~63.
    regex::Regex::new(
        r"(?i)^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z-]{0,61}[a-z]:\d{1,5}$",
    )
    .unwrap()
    .is_match(id)
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_mangle() {
        let addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(192, 168, 16, 32), 21116));
        assert_eq!(addr, AddrMangle::decode(&AddrMangle::encode(addr)));

        let addr = "[2001:db8::1]:8080".parse::<SocketAddr>().unwrap();
        assert_eq!(addr, AddrMangle::decode(&AddrMangle::encode(addr)));

        let addr = "[2001:db8:ff::1111]:80".parse::<SocketAddr>().unwrap();
        assert_eq!(addr, AddrMangle::decode(&AddrMangle::encode(addr)));
    }

    #[test]
    fn test_allow_err() {
        allow_err!(Err("test err") as Result<(), &str>);
        allow_err!(
            Err("test err with msg") as Result<(), &str>,
            "prompt {}",
            "failed"
        );
    }

    #[test]
    fn test_ipv6() {
        assert!(is_ipv6_str("1:2:3"));
        assert!(is_ipv6_str("[ab:2:3]:12"));
        assert!(is_ipv6_str("[ABEF:2a:3]:12"));
        assert!(!is_ipv6_str("[ABEG:2a:3]:12"));
        assert!(!is_ipv6_str("1[ab:2:3]:12"));
        assert!(!is_ipv6_str("1.1.1.1"));
        assert!(is_ip_str("1.1.1.1"));
        assert!(!is_ipv6_str("1:2:"));
        assert!(is_ipv6_str("1:2::0"));
        assert!(is_ipv6_str("[1:2::0]:1"));
        assert!(!is_ipv6_str("[1:2::0]:"));
        assert!(!is_ipv6_str("1:2::0]:1"));
    }

    #[test]
    fn test_hostname_port() {
        assert!(!is_domain_port_str("a:12"));
        assert!(!is_domain_port_str("a.b.c:12"));
        assert!(is_domain_port_str("test.com:12"));
        assert!(is_domain_port_str("test-UPPER.com:12"));
        assert!(is_domain_port_str("some-other.domain.com:12"));
        assert!(!is_domain_port_str("under_score:12"));
        assert!(!is_domain_port_str("a@bc:12"));
        assert!(!is_domain_port_str("1.1.1.1:12"));
        assert!(!is_domain_port_str("1.2.3:12"));
        assert!(!is_domain_port_str("1.2.3.45:12"));
        assert!(!is_domain_port_str("a.b.c:123456"));
        assert!(!is_domain_port_str("---:12"));
        assert!(!is_domain_port_str(".:12"));
        // todo: should we also check for these edge cases?
        // out-of-range port
        assert!(is_domain_port_str("test.com:0"));
        assert!(is_domain_port_str("test.com:98989"));
    }

    #[test]
    fn test_mangle2() {
        let addr = "[::ffff:127.0.0.1]:8080".parse().unwrap();
        let addr_v4 = "127.0.0.1:8080".parse().unwrap();
        assert_eq!(AddrMangle::decode(&AddrMangle::encode(addr)), addr_v4);
        assert_eq!(
            AddrMangle::decode(&AddrMangle::encode("[::127.0.0.1]:8080".parse().unwrap())),
            addr_v4
        );
        assert_eq!(AddrMangle::decode(&AddrMangle::encode(addr_v4)), addr_v4);
        let addr_v6 = "[ef::fe]:8080".parse().unwrap();
        assert_eq!(AddrMangle::decode(&AddrMangle::encode(addr_v6)), addr_v6);
        let addr_v6 = "[::1]:8080".parse().unwrap();
        assert_eq!(AddrMangle::decode(&AddrMangle::encode(addr_v6)), addr_v6);
    }
}
