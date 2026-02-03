//! FFI Bindings for AMT Protocol
//!
//! Exposes Rust AMT protocol implementation via C-compatible FFI.
//! Used for CGO (Caddy), JNI (Android), and UniFFI (iOS) bindings.
//!
//! ## Memory Management
//!
//! The FFI uses opaque handles for gateway instances. Callers must:
//! - Call `amt_gateway_new` to create a gateway, receiving a handle
//! - Call `amt_gateway_free` when done to release memory
//! - All byte buffers returned are owned by Rust - call `amt_buffer_free` to release
//!
//! ## Error Handling
//!
//! Functions return error codes via `AmtResult`. Zero indicates success,
//! non-zero indicates an error. Call `amt_error_message` to get error details.

use std::ffi::{CStr, CString, c_char, c_void};
use std::net::IpAddr;
use std::ptr;
use std::sync::Arc;

use crate::gateway::AmtGateway;
use crate::config::AmtConfig;
use crate::messages::AmtMessage;
use crate::platform::ffi_platform::FfiPlatform;

/// Opaque handle to AMT Gateway
pub type AmtGatewayHandle = *mut c_void;

/// Result codes for FFI functions
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AmtResult {
    /// Operation succeeded
    Ok = 0,
    /// Invalid argument provided
    InvalidArgument = 1,
    /// Invalid state for operation
    InvalidState = 2,
    /// Invalid nonce in response
    InvalidNonce = 3,
    /// No response MAC available
    NoResponseMac = 4,
    /// Message decode error
    DecodeError = 5,
    /// Memory allocation error
    AllocationError = 6,
    /// Null pointer provided
    NullPointer = 7,
    /// Unknown error
    Unknown = 99,
}

impl From<crate::error::AmtError> for AmtResult {
    fn from(err: crate::error::AmtError) -> Self {
        match err {
            crate::error::AmtError::InvalidState => AmtResult::InvalidState,
            crate::error::AmtError::InvalidNonce => AmtResult::InvalidNonce,
            crate::error::AmtError::NoResponseMac => AmtResult::NoResponseMac,
            crate::error::AmtError::InvalidMessage(_) => AmtResult::DecodeError,
            crate::error::AmtError::UnexpectedMessage => AmtResult::InvalidArgument,
            crate::error::AmtError::IoError(_) => AmtResult::Unknown,
        }
    }
}

/// Gateway state enum for FFI
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AmtGatewayState {
    Idle = 0,
    Discovering = 1,
    Requesting = 2,
    Querying = 3,
    Active = 4,
    Closed = 5,
}

impl From<crate::gateway::GatewayState> for AmtGatewayState {
    fn from(state: crate::gateway::GatewayState) -> Self {
        match state {
            crate::gateway::GatewayState::Idle => AmtGatewayState::Idle,
            crate::gateway::GatewayState::Discovering => AmtGatewayState::Discovering,
            crate::gateway::GatewayState::Requesting => AmtGatewayState::Requesting,
            crate::gateway::GatewayState::Querying => AmtGatewayState::Querying,
            crate::gateway::GatewayState::Active => AmtGatewayState::Active,
            crate::gateway::GatewayState::Closed => AmtGatewayState::Closed,
        }
    }
}

/// Buffer returned from FFI functions
///
/// Caller must free with `amt_buffer_free`
#[repr(C)]
pub struct AmtBuffer {
    pub data: *mut u8,
    pub len: usize,
    pub capacity: usize,
}

impl AmtBuffer {
    fn from_vec(mut vec: Vec<u8>) -> Self {
        let ptr = vec.as_mut_ptr();
        let len = vec.len();
        let capacity = vec.capacity();
        std::mem::forget(vec);
        AmtBuffer {
            data: ptr,
            len,
            capacity,
        }
    }

    fn null() -> Self {
        AmtBuffer {
            data: ptr::null_mut(),
            len: 0,
            capacity: 0,
        }
    }
}

// ============================================================================
// Gateway Lifecycle
// ============================================================================

/// Create a new AMT Gateway
///
/// # Arguments
/// - `relay_address`: Null-terminated C string with relay IP address
/// - `relay_port`: Relay port (use 0 for default 2268)
/// - `enable_driad`: Enable DRIAD discovery
/// - `out_handle`: Pointer to receive gateway handle
///
/// # Returns
/// AmtResult indicating success or failure
#[no_mangle]
pub extern "C" fn amt_gateway_new(
    relay_address: *const c_char,
    relay_port: u16,
    enable_driad: bool,
    out_handle: *mut AmtGatewayHandle,
) -> AmtResult {
    if relay_address.is_null() || out_handle.is_null() {
        return AmtResult::NullPointer;
    }

    let relay_str = unsafe {
        match CStr::from_ptr(relay_address).to_str() {
            Ok(s) => s,
            Err(_) => return AmtResult::InvalidArgument,
        }
    };

    let addr: IpAddr = match relay_str.parse() {
        Ok(a) => a,
        Err(_) => return AmtResult::InvalidArgument,
    };

    let port = if relay_port == 0 { None } else { Some(relay_port) };

    let config = if enable_driad {
        AmtConfig::with_driad(addr, port)
    } else {
        AmtConfig::new(addr, port)
    };

    let platform = Arc::new(FfiPlatform::new());
    let gateway = Box::new(AmtGateway::new(config, platform));
    let handle = Box::into_raw(gateway) as AmtGatewayHandle;

    unsafe {
        *out_handle = handle;
    }

    AmtResult::Ok
}

/// Free an AMT Gateway
///
/// # Arguments
/// - `handle`: Gateway handle from `amt_gateway_new`
#[no_mangle]
pub extern "C" fn amt_gateway_free(handle: AmtGatewayHandle) {
    if !handle.is_null() {
        unsafe {
            drop(Box::from_raw(handle as *mut AmtGateway<FfiPlatform>));
        }
    }
}

/// Free a buffer returned from FFI functions
///
/// # Arguments
/// - `buffer`: Buffer to free
#[no_mangle]
pub extern "C" fn amt_buffer_free(buffer: AmtBuffer) {
    if !buffer.data.is_null() {
        unsafe {
            drop(Vec::from_raw_parts(buffer.data, buffer.len, buffer.capacity));
        }
    }
}

// ============================================================================
// Gateway State
// ============================================================================

/// Get current gateway state
///
/// # Arguments
/// - `handle`: Gateway handle
///
/// # Returns
/// Current state as AmtGatewayState
#[no_mangle]
pub extern "C" fn amt_gateway_state(handle: AmtGatewayHandle) -> AmtGatewayState {
    if handle.is_null() {
        return AmtGatewayState::Idle;
    }

    let gateway = unsafe { &*(handle as *const AmtGateway<FfiPlatform>) };
    gateway.state().into()
}

/// Get current relay port
///
/// # Arguments
/// - `handle`: Gateway handle
///
/// # Returns
/// Current relay port
#[no_mangle]
pub extern "C" fn amt_gateway_relay_port(handle: AmtGatewayHandle) -> u16 {
    if handle.is_null() {
        return 0;
    }

    let gateway = unsafe { &*(handle as *const AmtGateway<FfiPlatform>) };
    gateway.relay_port()
}

// ============================================================================
// Protocol Operations
// ============================================================================

/// Start relay discovery
///
/// # Arguments
/// - `handle`: Gateway handle
/// - `out_message`: Pointer to receive encoded message buffer
///
/// # Returns
/// AmtResult indicating success or failure
#[no_mangle]
pub extern "C" fn amt_gateway_start_discovery(
    handle: AmtGatewayHandle,
    out_message: *mut AmtBuffer,
) -> AmtResult {
    if handle.is_null() || out_message.is_null() {
        return AmtResult::NullPointer;
    }

    let gateway = unsafe { &mut *(handle as *mut AmtGateway<FfiPlatform>) };

    match gateway.start_discovery() {
        Ok(msg) => {
            let encoded = msg.encode();
            unsafe {
                *out_message = AmtBuffer::from_vec(encoded);
            }
            AmtResult::Ok
        }
        Err(e) => {
            unsafe {
                *out_message = AmtBuffer::null();
            }
            e.into()
        }
    }
}

/// Handle relay advertisement response
///
/// # Arguments
/// - `handle`: Gateway handle
/// - `data`: Advertisement message bytes
/// - `len`: Length of data
///
/// # Returns
/// AmtResult indicating success or failure
#[no_mangle]
pub extern "C" fn amt_gateway_handle_advertisement(
    handle: AmtGatewayHandle,
    data: *const u8,
    len: usize,
) -> AmtResult {
    if handle.is_null() || data.is_null() {
        return AmtResult::NullPointer;
    }

    let gateway = unsafe { &mut *(handle as *mut AmtGateway<FfiPlatform>) };
    let bytes = unsafe { std::slice::from_raw_parts(data, len) };

    let msg = match AmtMessage::decode(bytes) {
        Ok(m) => m,
        Err(_) => return AmtResult::DecodeError,
    };

    match msg {
        AmtMessage::RelayAdvertisement { nonce, relay_address } => {
            match gateway.handle_advertisement(nonce, relay_address) {
                Ok(()) => AmtResult::Ok,
                Err(e) => e.into(),
            }
        }
        _ => AmtResult::InvalidArgument,
    }
}

/// Request membership
///
/// # Arguments
/// - `handle`: Gateway handle
/// - `p_flag`: Prefer native multicast flag
/// - `out_message`: Pointer to receive encoded message buffer
///
/// # Returns
/// AmtResult indicating success or failure
#[no_mangle]
pub extern "C" fn amt_gateway_request_membership(
    handle: AmtGatewayHandle,
    p_flag: bool,
    out_message: *mut AmtBuffer,
) -> AmtResult {
    if handle.is_null() || out_message.is_null() {
        return AmtResult::NullPointer;
    }

    let gateway = unsafe { &mut *(handle as *mut AmtGateway<FfiPlatform>) };

    match gateway.request_membership(p_flag) {
        Ok(msg) => {
            let encoded = msg.encode();
            unsafe {
                *out_message = AmtBuffer::from_vec(encoded);
            }
            AmtResult::Ok
        }
        Err(e) => {
            unsafe {
                *out_message = AmtBuffer::null();
            }
            e.into()
        }
    }
}

/// Handle membership query response
///
/// # Arguments
/// - `handle`: Gateway handle
/// - `data`: Query message bytes
/// - `len`: Length of data
/// - `out_query_data`: Pointer to receive IGMP/MLD query data
///
/// # Returns
/// AmtResult indicating success or failure
#[no_mangle]
pub extern "C" fn amt_gateway_handle_query(
    handle: AmtGatewayHandle,
    data: *const u8,
    len: usize,
    out_query_data: *mut AmtBuffer,
) -> AmtResult {
    if handle.is_null() || data.is_null() || out_query_data.is_null() {
        return AmtResult::NullPointer;
    }

    let gateway = unsafe { &mut *(handle as *mut AmtGateway<FfiPlatform>) };
    let bytes = unsafe { std::slice::from_raw_parts(data, len) };

    let msg = match AmtMessage::decode(bytes) {
        Ok(m) => m,
        Err(_) => return AmtResult::DecodeError,
    };

    match msg {
        AmtMessage::MembershipQuery { request_nonce, response_mac, query_data } => {
            match gateway.handle_query(request_nonce, response_mac, query_data) {
                Ok(data) => {
                    unsafe {
                        *out_query_data = AmtBuffer::from_vec(data);
                    }
                    AmtResult::Ok
                }
                Err(e) => {
                    unsafe {
                        *out_query_data = AmtBuffer::null();
                    }
                    e.into()
                }
            }
        }
        _ => {
            unsafe {
                *out_query_data = AmtBuffer::null();
            }
            AmtResult::InvalidArgument
        }
    }
}

/// Send membership update
///
/// # Arguments
/// - `handle`: Gateway handle
/// - `report_data`: IGMP/MLD report bytes
/// - `report_len`: Length of report data
/// - `out_message`: Pointer to receive encoded message buffer
///
/// # Returns
/// AmtResult indicating success or failure
#[no_mangle]
pub extern "C" fn amt_gateway_send_update(
    handle: AmtGatewayHandle,
    report_data: *const u8,
    report_len: usize,
    out_message: *mut AmtBuffer,
) -> AmtResult {
    if handle.is_null() || report_data.is_null() || out_message.is_null() {
        return AmtResult::NullPointer;
    }

    let gateway = unsafe { &mut *(handle as *mut AmtGateway<FfiPlatform>) };
    let report = unsafe { std::slice::from_raw_parts(report_data, report_len) }.to_vec();

    match gateway.send_update(report) {
        Ok(msg) => {
            let encoded = msg.encode();
            unsafe {
                *out_message = AmtBuffer::from_vec(encoded);
            }
            AmtResult::Ok
        }
        Err(e) => {
            unsafe {
                *out_message = AmtBuffer::null();
            }
            e.into()
        }
    }
}

/// Handle multicast data
///
/// # Arguments
/// - `handle`: Gateway handle
/// - `data`: Data message bytes
/// - `len`: Length of data
/// - `out_packet`: Pointer to receive IP packet
///
/// # Returns
/// AmtResult indicating success or failure
#[no_mangle]
pub extern "C" fn amt_gateway_handle_data(
    handle: AmtGatewayHandle,
    data: *const u8,
    len: usize,
    out_packet: *mut AmtBuffer,
) -> AmtResult {
    if handle.is_null() || data.is_null() || out_packet.is_null() {
        return AmtResult::NullPointer;
    }

    let gateway = unsafe { &*(handle as *const AmtGateway<FfiPlatform>) };
    let bytes = unsafe { std::slice::from_raw_parts(data, len) };

    let msg = match AmtMessage::decode(bytes) {
        Ok(m) => m,
        Err(_) => return AmtResult::DecodeError,
    };

    match msg {
        AmtMessage::MulticastData { ip_packet } => {
            match gateway.handle_data(ip_packet) {
                Ok(packet) => {
                    unsafe {
                        *out_packet = AmtBuffer::from_vec(packet);
                    }
                    AmtResult::Ok
                }
                Err(e) => {
                    unsafe {
                        *out_packet = AmtBuffer::null();
                    }
                    e.into()
                }
            }
        }
        _ => {
            unsafe {
                *out_packet = AmtBuffer::null();
            }
            AmtResult::InvalidArgument
        }
    }
}

/// Send teardown message
///
/// # Arguments
/// - `handle`: Gateway handle
/// - `out_message`: Pointer to receive encoded message buffer
///
/// # Returns
/// AmtResult indicating success or failure
#[no_mangle]
pub extern "C" fn amt_gateway_send_teardown(
    handle: AmtGatewayHandle,
    out_message: *mut AmtBuffer,
) -> AmtResult {
    if handle.is_null() || out_message.is_null() {
        return AmtResult::NullPointer;
    }

    let gateway = unsafe { &mut *(handle as *mut AmtGateway<FfiPlatform>) };

    match gateway.send_teardown() {
        Ok(msg) => {
            let encoded = msg.encode();
            unsafe {
                *out_message = AmtBuffer::from_vec(encoded);
            }
            AmtResult::Ok
        }
        Err(e) => {
            unsafe {
                *out_message = AmtBuffer::null();
            }
            e.into()
        }
    }
}

/// Reset gateway to idle state
///
/// # Arguments
/// - `handle`: Gateway handle
#[no_mangle]
pub extern "C" fn amt_gateway_reset(handle: AmtGatewayHandle) {
    if !handle.is_null() {
        let gateway = unsafe { &mut *(handle as *mut AmtGateway<FfiPlatform>) };
        gateway.reset();
    }
}

// ============================================================================
// DRIAD Support
// ============================================================================

/// Build DRIAD query name for source address
///
/// # Arguments
/// - `source_address`: Null-terminated C string with source IP address
/// - `out_query`: Pointer to receive query name (null-terminated C string)
///
/// # Returns
/// AmtResult indicating success or failure
///
/// # Note
/// Caller must free the returned string with `amt_string_free`
#[no_mangle]
pub extern "C" fn amt_driad_build_query(
    source_address: *const c_char,
    out_query: *mut *mut c_char,
) -> AmtResult {
    if source_address.is_null() || out_query.is_null() {
        return AmtResult::NullPointer;
    }

    let source_str = unsafe {
        match CStr::from_ptr(source_address).to_str() {
            Ok(s) => s,
            Err(_) => return AmtResult::InvalidArgument,
        }
    };

    let addr: IpAddr = match source_str.parse() {
        Ok(a) => a,
        Err(_) => return AmtResult::InvalidArgument,
    };

    let query = crate::driad::DriadResolver::build_query(addr);

    match CString::new(query) {
        Ok(cstr) => {
            unsafe {
                *out_query = cstr.into_raw();
            }
            AmtResult::Ok
        }
        Err(_) => AmtResult::AllocationError,
    }
}

/// Free a string returned from FFI functions
///
/// # Arguments
/// - `s`: String to free
#[no_mangle]
pub extern "C" fn amt_string_free(s: *mut c_char) {
    if !s.is_null() {
        unsafe {
            drop(CString::from_raw(s));
        }
    }
}

// ============================================================================
// IGMP Report Generation
// ============================================================================

/// Create an IGMPv3 SSM join report with IP encapsulation
///
/// Creates a complete IP-encapsulated IGMPv3 membership report for joining
/// a source-specific multicast group.
///
/// # Arguments
/// - `source_address`: Null-terminated C string with multicast source IP (IPv4)
/// - `group_address`: Null-terminated C string with multicast group IP (IPv4)
/// - `out_report`: Pointer to receive encoded report buffer
///
/// # Returns
/// AmtResult indicating success or failure
#[no_mangle]
pub extern "C" fn amt_igmp_ssm_join(
    source_address: *const c_char,
    group_address: *const c_char,
    out_report: *mut AmtBuffer,
) -> AmtResult {
    if source_address.is_null() || group_address.is_null() || out_report.is_null() {
        return AmtResult::NullPointer;
    }

    let source_str = unsafe {
        match CStr::from_ptr(source_address).to_str() {
            Ok(s) => s,
            Err(_) => return AmtResult::InvalidArgument,
        }
    };

    let group_str = unsafe {
        match CStr::from_ptr(group_address).to_str() {
            Ok(s) => s,
            Err(_) => return AmtResult::InvalidArgument,
        }
    };

    let source: std::net::Ipv4Addr = match source_str.parse() {
        Ok(a) => a,
        Err(_) => return AmtResult::InvalidArgument,
    };

    let group: std::net::Ipv4Addr = match group_str.parse() {
        Ok(a) => a,
        Err(_) => return AmtResult::InvalidArgument,
    };

    // Create SSM join report
    let mut report = crate::igmp::IgmpV3Report::new();
    report.add_record(crate::igmp::IgmpRecord::ssm_join(group, source));

    // Encode with IP encapsulation
    let encoded = report.encode_with_ip(source, group);

    unsafe {
        *out_report = AmtBuffer::from_vec(encoded);
    }

    AmtResult::Ok
}

/// Create an IGMPv3 multi-group SSM join report with IP encapsulation
///
/// Creates a complete IP-encapsulated IGMPv3 membership report for joining
/// multiple source-specific multicast groups from the same source.
///
/// # Arguments
/// - `source_address`: Null-terminated C string with multicast source IP (IPv4)
/// - `group_addresses`: Array of null-terminated C strings with group IPs
/// - `num_groups`: Number of groups in the array
/// - `out_report`: Pointer to receive encoded report buffer
///
/// # Returns
/// AmtResult indicating success or failure
#[no_mangle]
pub extern "C" fn amt_igmp_ssm_join_multi(
    source_address: *const c_char,
    group_addresses: *const *const c_char,
    num_groups: usize,
    out_report: *mut AmtBuffer,
) -> AmtResult {
    if source_address.is_null() || group_addresses.is_null() || out_report.is_null() || num_groups == 0 {
        return AmtResult::NullPointer;
    }

    let source_str = unsafe {
        match CStr::from_ptr(source_address).to_str() {
            Ok(s) => s,
            Err(_) => return AmtResult::InvalidArgument,
        }
    };

    let source: std::net::Ipv4Addr = match source_str.parse() {
        Ok(a) => a,
        Err(_) => return AmtResult::InvalidArgument,
    };

    // Parse all group addresses
    let mut groups = Vec::with_capacity(num_groups);
    for i in 0..num_groups {
        let group_ptr = unsafe { *group_addresses.add(i) };
        if group_ptr.is_null() {
            return AmtResult::NullPointer;
        }

        let group_str = unsafe {
            match CStr::from_ptr(group_ptr).to_str() {
                Ok(s) => s,
                Err(_) => return AmtResult::InvalidArgument,
            }
        };

        let group: std::net::Ipv4Addr = match group_str.parse() {
            Ok(a) => a,
            Err(_) => return AmtResult::InvalidArgument,
        };

        groups.push(group);
    }

    // Create SSM join report with all groups
    let mut report = crate::igmp::IgmpV3Report::new();
    for group in &groups {
        report.add_record(crate::igmp::IgmpRecord::ssm_join(*group, source));
    }

    // Use first group for IP header destination (common practice)
    let first_group = groups[0];
    let encoded = report.encode_with_ip(source, first_group);

    unsafe {
        *out_report = AmtBuffer::from_vec(encoded);
    }

    AmtResult::Ok
}

// ============================================================================
// Version Info
// ============================================================================

/// Get library version
///
/// # Returns
/// Null-terminated C string with version (static, do not free)
#[no_mangle]
pub extern "C" fn amt_version() -> *const c_char {
    static VERSION: &[u8] = b"0.1.0\0";
    VERSION.as_ptr() as *const c_char
}
