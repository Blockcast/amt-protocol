//! JNI Bindings for AMT Protocol (Android)
//!
//! Exposes Rust AMT protocol implementation to Kotlin/Java via JNI.
//!
//! ## Kotlin Usage
//!
//! ```kotlin
//! val gateway = AmtGateway.create("162.250.138.201", 2268)
//! val discoveryMsg = gateway.startDiscovery()
//! // Send discoveryMsg to relay...
//! gateway.close()
//! ```

use jni::JNIEnv;
use jni::objects::{JClass, JString, JByteArray, JObjectArray};
use jni::sys::{jlong, jint, jboolean, jbyteArray};
use std::sync::Arc;
use std::net::Ipv4Addr;

use crate::gateway::AmtGateway;
use crate::config::AmtConfig;
use crate::messages::AmtMessage;
use crate::platform::ffi_platform::FfiPlatform;
use crate::igmp::{IgmpV3Report, IgmpRecord};

/// Type alias for the gateway with FFI platform
type GatewayHandle = AmtGateway<FfiPlatform>;

/// Convert gateway to JNI handle (pointer as jlong)
fn to_handle(gw: GatewayHandle) -> jlong {
    Box::into_raw(Box::new(gw)) as jlong
}

/// Convert JNI handle back to gateway reference
///
/// # Safety
/// Handle must be a valid pointer from `to_handle`
unsafe fn from_handle<'a>(handle: jlong) -> &'a mut GatewayHandle {
    &mut *(handle as *mut GatewayHandle)
}

// ============================================================================
// Gateway Lifecycle
// ============================================================================

/// Create a new AMT Gateway
///
/// JNI signature: (Ljava/lang/String;IZ)J
#[no_mangle]
pub extern "system" fn Java_com_blockcast_sdk_amt_AmtGateway_nativeCreate(
    mut env: JNIEnv,
    _class: JClass,
    relay_address: JString,
    relay_port: jint,
    enable_driad: jboolean,
) -> jlong {
    let addr_str: String = match env.get_string(&relay_address) {
        Ok(s) => s.into(),
        Err(_) => return 0,
    };

    let addr = match addr_str.parse() {
        Ok(a) => a,
        Err(_) => return 0,
    };

    let port = if relay_port <= 0 { None } else { Some(relay_port as u16) };

    let config = if enable_driad != 0 {
        AmtConfig::with_driad(addr, port)
    } else {
        AmtConfig::new(addr, port)
    };

    let platform = Arc::new(FfiPlatform::new());
    let gateway = AmtGateway::new(config, platform);

    to_handle(gateway)
}

/// Destroy an AMT Gateway
///
/// JNI signature: (J)V
#[no_mangle]
pub extern "system" fn Java_com_blockcast_sdk_amt_AmtGateway_nativeDestroy(
    _env: JNIEnv,
    _class: JClass,
    handle: jlong,
) {
    if handle != 0 {
        unsafe {
            drop(Box::from_raw(handle as *mut GatewayHandle));
        }
    }
}

// ============================================================================
// Gateway State
// ============================================================================

/// Get current gateway state
///
/// JNI signature: (J)I
/// Returns: 0=Idle, 1=Discovering, 2=Requesting, 3=Querying, 4=Active, 5=Closed, -1=Error
#[no_mangle]
pub extern "system" fn Java_com_blockcast_sdk_amt_AmtGateway_nativeGetState(
    _env: JNIEnv,
    _class: JClass,
    handle: jlong,
) -> jint {
    if handle == 0 {
        return -1;
    }

    let gw = unsafe { from_handle(handle) };
    match gw.state() {
        crate::gateway::GatewayState::Idle => 0,
        crate::gateway::GatewayState::Discovering => 1,
        crate::gateway::GatewayState::Requesting => 2,
        crate::gateway::GatewayState::Querying => 3,
        crate::gateway::GatewayState::Active => 4,
        crate::gateway::GatewayState::Closed => 5,
    }
}

/// Get current relay port
///
/// JNI signature: (J)I
#[no_mangle]
pub extern "system" fn Java_com_blockcast_sdk_amt_AmtGateway_nativeGetRelayPort(
    _env: JNIEnv,
    _class: JClass,
    handle: jlong,
) -> jint {
    if handle == 0 {
        return 0;
    }

    let gw = unsafe { from_handle(handle) };
    gw.relay_port() as jint
}

// ============================================================================
// Protocol Operations
// ============================================================================

/// Start relay discovery
///
/// JNI signature: (J)[B
/// Returns encoded RelayDiscovery message or null on error
#[no_mangle]
pub extern "system" fn Java_com_blockcast_sdk_amt_AmtGateway_nativeStartDiscovery<'local>(
    env: JNIEnv<'local>,
    _class: JClass,
    handle: jlong,
) -> jbyteArray {
    if handle == 0 {
        return std::ptr::null_mut();
    }

    let gw = unsafe { from_handle(handle) };

    match gw.start_discovery() {
        Ok(msg) => {
            let bytes = msg.encode();
            match env.byte_array_from_slice(&bytes) {
                Ok(arr) => arr.into_raw(),
                Err(_) => std::ptr::null_mut(),
            }
        }
        Err(_) => std::ptr::null_mut(),
    }
}

/// Handle relay advertisement
///
/// JNI signature: (J[B)I
/// Returns 0 on success, error code on failure
#[no_mangle]
pub extern "system" fn Java_com_blockcast_sdk_amt_AmtGateway_nativeHandleAdvertisement(
    env: JNIEnv,
    _class: JClass,
    handle: jlong,
    data: JByteArray,
) -> jint {
    if handle == 0 {
        return -1;
    }

    let gw = unsafe { from_handle(handle) };

    let bytes = match env.convert_byte_array(data) {
        Ok(b) => b,
        Err(_) => return -2,
    };

    let msg = match AmtMessage::decode(&bytes) {
        Ok(m) => m,
        Err(_) => return -3,
    };

    match msg {
        AmtMessage::RelayAdvertisement { nonce, relay_address } => {
            match gw.handle_advertisement(nonce, relay_address) {
                Ok(()) => 0,
                Err(_) => -4,
            }
        }
        _ => -5,
    }
}

/// Request membership
///
/// JNI signature: (JZ)[B
/// Returns encoded Request message or null on error
#[no_mangle]
pub extern "system" fn Java_com_blockcast_sdk_amt_AmtGateway_nativeRequestMembership<'local>(
    env: JNIEnv<'local>,
    _class: JClass,
    handle: jlong,
    p_flag: jboolean,
) -> jbyteArray {
    if handle == 0 {
        return std::ptr::null_mut();
    }

    let gw = unsafe { from_handle(handle) };

    match gw.request_membership(p_flag != 0) {
        Ok(msg) => {
            let bytes = msg.encode();
            match env.byte_array_from_slice(&bytes) {
                Ok(arr) => arr.into_raw(),
                Err(_) => std::ptr::null_mut(),
            }
        }
        Err(_) => std::ptr::null_mut(),
    }
}

/// Handle membership query
///
/// JNI signature: (J[B)[B
/// Returns IGMP/MLD query data or null on error
#[no_mangle]
pub extern "system" fn Java_com_blockcast_sdk_amt_AmtGateway_nativeHandleQuery<'local>(
    env: JNIEnv<'local>,
    _class: JClass,
    handle: jlong,
    data: JByteArray,
) -> jbyteArray {
    if handle == 0 {
        return std::ptr::null_mut();
    }

    let gw = unsafe { from_handle(handle) };

    let bytes = match env.convert_byte_array(data) {
        Ok(b) => b,
        Err(_) => return std::ptr::null_mut(),
    };

    let msg = match AmtMessage::decode(&bytes) {
        Ok(m) => m,
        Err(_) => return std::ptr::null_mut(),
    };

    match msg {
        AmtMessage::MembershipQuery { request_nonce, response_mac, query_data } => {
            match gw.handle_query(request_nonce, response_mac, query_data) {
                Ok(data) => {
                    match env.byte_array_from_slice(&data) {
                        Ok(arr) => arr.into_raw(),
                        Err(_) => std::ptr::null_mut(),
                    }
                }
                Err(_) => std::ptr::null_mut(),
            }
        }
        _ => std::ptr::null_mut(),
    }
}

/// Send membership update
///
/// JNI signature: (J[B)[B
/// Returns encoded MembershipUpdate message or null on error
#[no_mangle]
pub extern "system" fn Java_com_blockcast_sdk_amt_AmtGateway_nativeSendUpdate<'local>(
    env: JNIEnv<'local>,
    _class: JClass,
    handle: jlong,
    report_data: JByteArray,
) -> jbyteArray {
    if handle == 0 {
        return std::ptr::null_mut();
    }

    let gw = unsafe { from_handle(handle) };

    let report = match env.convert_byte_array(report_data) {
        Ok(b) => b,
        Err(_) => return std::ptr::null_mut(),
    };

    match gw.send_update(report) {
        Ok(msg) => {
            let bytes = msg.encode();
            match env.byte_array_from_slice(&bytes) {
                Ok(arr) => arr.into_raw(),
                Err(_) => std::ptr::null_mut(),
            }
        }
        Err(_) => std::ptr::null_mut(),
    }
}

/// Handle multicast data
///
/// JNI signature: (J[B)[B
/// Returns IP packet or null on error
#[no_mangle]
pub extern "system" fn Java_com_blockcast_sdk_amt_AmtGateway_nativeHandleData<'local>(
    env: JNIEnv<'local>,
    _class: JClass,
    handle: jlong,
    data: JByteArray,
) -> jbyteArray {
    if handle == 0 {
        return std::ptr::null_mut();
    }

    let gw = unsafe { from_handle(handle) };

    let bytes = match env.convert_byte_array(data) {
        Ok(b) => b,
        Err(_) => return std::ptr::null_mut(),
    };

    let msg = match AmtMessage::decode(&bytes) {
        Ok(m) => m,
        Err(_) => return std::ptr::null_mut(),
    };

    match msg {
        AmtMessage::MulticastData { ip_packet } => {
            match gw.handle_data(ip_packet) {
                Ok(packet) => {
                    match env.byte_array_from_slice(&packet) {
                        Ok(arr) => arr.into_raw(),
                        Err(_) => std::ptr::null_mut(),
                    }
                }
                Err(_) => std::ptr::null_mut(),
            }
        }
        _ => std::ptr::null_mut(),
    }
}

/// Send teardown
///
/// JNI signature: (J)[B
/// Returns encoded Teardown message or null on error
#[no_mangle]
pub extern "system" fn Java_com_blockcast_sdk_amt_AmtGateway_nativeSendTeardown<'local>(
    env: JNIEnv<'local>,
    _class: JClass,
    handle: jlong,
) -> jbyteArray {
    if handle == 0 {
        return std::ptr::null_mut();
    }

    let gw = unsafe { from_handle(handle) };

    match gw.send_teardown() {
        Ok(msg) => {
            let bytes = msg.encode();
            match env.byte_array_from_slice(&bytes) {
                Ok(arr) => arr.into_raw(),
                Err(_) => std::ptr::null_mut(),
            }
        }
        Err(_) => std::ptr::null_mut(),
    }
}

/// Reset gateway to idle state
///
/// JNI signature: (J)V
#[no_mangle]
pub extern "system" fn Java_com_blockcast_sdk_amt_AmtGateway_nativeReset(
    _env: JNIEnv,
    _class: JClass,
    handle: jlong,
) {
    if handle != 0 {
        let gw = unsafe { from_handle(handle) };
        gw.reset();
    }
}

// ============================================================================
// DRIAD Support
// ============================================================================

/// Build DRIAD query name
///
/// JNI signature: (Ljava/lang/String;)Ljava/lang/String;
#[no_mangle]
pub extern "system" fn Java_com_blockcast_sdk_amt_Driad_nativeBuildQuery<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass,
    source_address: JString,
) -> jni::sys::jstring {
    let addr_str: String = match env.get_string(&source_address) {
        Ok(s) => s.into(),
        Err(_) => return std::ptr::null_mut(),
    };

    let addr = match addr_str.parse() {
        Ok(a) => a,
        Err(_) => return std::ptr::null_mut(),
    };

    let query = crate::driad::DriadResolver::build_query(addr);

    match env.new_string(query) {
        Ok(s) => s.into_raw(),
        Err(_) => std::ptr::null_mut(),
    }
}

// ============================================================================
// IGMP SSM Support
// ============================================================================

/// Create IGMPv3 SSM join report for a single (S,G) pair
///
/// JNI signature: (Ljava/lang/String;Ljava/lang/String;)[B
/// Returns IP-encapsulated IGMPv3 membership report or null on error
#[no_mangle]
pub extern "system" fn Java_com_blockcast_sdk_amt_IgmpSsm_nativeCreateJoinReport<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass,
    source_address: JString,
    group_address: JString,
) -> jbyteArray {
    // Parse source address
    let source_str: String = match env.get_string(&source_address) {
        Ok(s) => s.into(),
        Err(_) => return std::ptr::null_mut(),
    };
    let source: Ipv4Addr = match source_str.parse() {
        Ok(a) => a,
        Err(_) => return std::ptr::null_mut(),
    };

    // Parse group address
    let group_str: String = match env.get_string(&group_address) {
        Ok(s) => s.into(),
        Err(_) => return std::ptr::null_mut(),
    };
    let group: Ipv4Addr = match group_str.parse() {
        Ok(a) => a,
        Err(_) => return std::ptr::null_mut(),
    };

    // Create IGMPv3 report with single SSM join record
    let mut report = IgmpV3Report::new();
    report.add_record(IgmpRecord::ssm_join(group, source));

    // Encode with IPv4 encapsulation (source IP = multicast source, dest IP = group)
    let encoded = report.encode_with_ip(source, group);

    match env.byte_array_from_slice(&encoded) {
        Ok(arr) => arr.into_raw(),
        Err(_) => std::ptr::null_mut(),
    }
}

/// Create IGMPv3 SSM join report for multiple groups from the same source
///
/// JNI signature: (Ljava/lang/String;[Ljava/lang/String;)[B
/// Returns IP-encapsulated IGMPv3 membership report or null on error
#[no_mangle]
pub extern "system" fn Java_com_blockcast_sdk_amt_IgmpSsm_nativeCreateMultiJoinReport<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass,
    source_address: JString,
    group_addresses: JObjectArray<'local>,
) -> jbyteArray {
    // Parse source address
    let source_str: String = match env.get_string(&source_address) {
        Ok(s) => s.into(),
        Err(_) => return std::ptr::null_mut(),
    };
    let source: Ipv4Addr = match source_str.parse() {
        Ok(a) => a,
        Err(_) => return std::ptr::null_mut(),
    };

    // Get array length
    let array_len = match env.get_array_length(&group_addresses) {
        Ok(len) => len,
        Err(_) => return std::ptr::null_mut(),
    };

    if array_len == 0 {
        return std::ptr::null_mut();
    }

    // Parse all group addresses
    let mut groups: Vec<Ipv4Addr> = Vec::with_capacity(array_len as usize);
    for i in 0..array_len {
        let group_obj = match env.get_object_array_element(&group_addresses, i) {
            Ok(obj) => obj,
            Err(_) => return std::ptr::null_mut(),
        };

        // Convert JObject to JString
        let group_jstr = JString::from(group_obj);
        let group_str: String = match env.get_string(&group_jstr) {
            Ok(s) => s.into(),
            Err(_) => return std::ptr::null_mut(),
        };

        let group: Ipv4Addr = match group_str.parse() {
            Ok(a) => a,
            Err(_) => return std::ptr::null_mut(),
        };

        groups.push(group);
    }

    // Create IGMPv3 report with multiple SSM join records
    let mut report = IgmpV3Report::new();
    for group in &groups {
        report.add_record(IgmpRecord::ssm_join(*group, source));
    }

    // Encode with IPv4 encapsulation
    // For multi-group, use the first group as destination (relay will handle routing)
    let encoded = report.encode_with_ip(source, groups[0]);

    match env.byte_array_from_slice(&encoded) {
        Ok(arr) => arr.into_raw(),
        Err(_) => std::ptr::null_mut(),
    }
}

// ============================================================================
// Version Info
// ============================================================================

/// Get library version
///
/// JNI signature: ()Ljava/lang/String;
#[no_mangle]
pub extern "system" fn Java_com_blockcast_sdk_amt_AmtGateway_nativeGetVersion<'local>(
    env: JNIEnv<'local>,
    _class: JClass,
) -> jni::sys::jstring {
    match env.new_string("0.1.0") {
        Ok(s) => s.into_raw(),
        Err(_) => std::ptr::null_mut(),
    }
}
