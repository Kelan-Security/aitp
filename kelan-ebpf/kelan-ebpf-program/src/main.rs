#![no_std]
#![no_main]

use aya_bpf::{
    bindings::xdp_action,
    macros::{map, xdp},
    maps::HashMap,
    programs::XdpContext,
};
use aya_log_ebpf::info;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct SessionPermit {
    pub source_entity_prefix: [u8; 8],
    pub dest_entity_prefix: [u8; 8],
    pub intent: u16,
    pub trust_score: u8,
    pub verdict: u8,
    pub expires_at: u64,
    pub _pad: [u8; 4],
}

#[map]
static PERMIT_MAP: HashMap<u64, SessionPermit> = HashMap::with_max_entries(65536, 0);

#[map]
static STATS_MAP: HashMap<u32, u64> = HashMap::with_max_entries(16, 0);

#[xdp]
pub fn kelan_xdp(ctx: XdpContext) -> u32 {
    match try_kelan_xdp(ctx) {
        Ok(action) => action,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}

#[inline(always)]
fn try_kelan_xdp(ctx: XdpContext) -> Result<u32, ()> {
    let ethhdr = ptr_at::<EthHdr>(&ctx, 0)?;
    let eth_proto = u16::from_be(unsafe { (*ethhdr).ether_type });

    if eth_proto != ETH_P_IP && eth_proto != ETH_P_IPV6 {
        increment_stat(3);
        return Ok(xdp_action::XDP_PASS);
    }

    increment_stat(0);

    let ipv4hdr = ptr_at::<Ipv4Hdr>(&ctx, ETH_HDR_LEN)?;
    let proto = unsafe { (*ipv4hdr).proto };

    if proto != IPPROTO_UDP {
        increment_stat(3);
        return Ok(xdp_action::XDP_PASS);
    }

    let ip_hdr_len = ((unsafe { (*ipv4hdr).ihl_version } & 0x0F) * 4) as usize;
    let udphdr = ptr_at::<UdpHdr>(&ctx, ETH_HDR_LEN + ip_hdr_len)?;

    let dst_port = u16::from_be(unsafe { (*udphdr).dest });

    if dst_port != 9999 {
        increment_stat(3);
        return Ok(xdp_action::XDP_PASS);
    }

    let udp_payload_offset = ETH_HDR_LEN + ip_hdr_len + UDP_HDR_LEN;
    let aitp_hdr = ptr_at::<AitpMinHdr>(&ctx, udp_payload_offset)?;

    let version = unsafe { (*aitp_hdr).version };
    let session_id = u64::from_be(unsafe { (*aitp_hdr).session_id });

    if version != 3 {
        increment_stat(2);
        return Ok(xdp_action::XDP_DROP);
    }

    let permit = unsafe { PERMIT_MAP.get(&session_id) };

    match permit {
        None => {
            increment_stat(2);
            let flags = unsafe { (*aitp_hdr).flags };
            if flags & 0x01 != 0 {
                increment_stat(3);
                return Ok(xdp_action::XDP_PASS);
            }
            Ok(xdp_action::XDP_DROP)
        }
        Some(permit) => {
            if permit.verdict == 0 {
                increment_stat(2);
                return Ok(xdp_action::XDP_DROP);
            }
            increment_stat(1);
            Ok(xdp_action::XDP_PASS)
        }
    }
}

#[repr(C)]
struct EthHdr {
    dst_mac: [u8; 6],
    src_mac: [u8; 6],
    ether_type: u16,
}

#[repr(C)]
struct Ipv4Hdr {
    ihl_version: u8,
    tos: u8,
    tot_len: u16,
    id: u16,
    frag_off: u16,
    ttl: u8,
    proto: u8,
    check: u16,
    src_addr: u32,
    dst_addr: u32,
}

#[repr(C)]
struct UdpHdr {
    source: u16,
    dest: u16,
    len: u16,
    check: u16,
}

#[repr(C)]
struct AitpMinHdr {
    version: u8,
    flags: u8,
    intent: u16,
    session_id: u64,
}

const ETH_P_IP: u16 = 0x0800;
const ETH_P_IPV6: u16 = 0x86DD;
const IPPROTO_UDP: u8 = 17;
const ETH_HDR_LEN: usize = 14;
const UDP_HDR_LEN: usize = 8;

#[inline(always)]
fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Result<*const T, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = core::mem::size_of::<T>();

    if start + offset + len > end {
        return Err(());
    }

    Ok((start + offset) as *const T)
}

#[inline(always)]
fn increment_stat(key: u32) {
    if let Some(count) = unsafe { STATS_MAP.get_ptr_mut(&key) } {
        unsafe { *count += 1 };
    }
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
