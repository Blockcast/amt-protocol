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

use jni::objects::{JByteArray, JClass, JObjectArray, JString};
use jni::sys::{jboolean, jbyteArray, jint, jlong};
use jni::JNIEnv;
use std::net::Ipv4Addr;
use std::sync::Arc;

use crate::config::AmtConfig;
use crate::gateway::AmtGateway;
use crate::igmp::{IgmpRecord, IgmpV3Report};
use crate::messages::AmtMessage;
use crate::platform::ffi_platform::FfiPlatform;

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
/// JNI signature: (Ljava/lang/String;I)J
#[no_mangle]
pub extern "system" fn Java_com_blockcast_amt_AmtGateway_nativeCreate(
    mut env: JNIEnv,
    _class: JClass,
    relay_address: JString,
    relay_port: jint,
) -> jlong {
    let addr_str: String = match env.get_string(&relay_address) {
        Ok(s) => s.into(),
        Err(_) => return 0,
    };

    let addr = match addr_str.parse() {
        Ok(a) => a,
        Err(_) => return 0,
    };

    let port = if relay_port <= 0 {
        None
    } else {
        Some(relay_port as u16)
    };

    let config = AmtConfig::new(addr, port);

    let platform = Arc::new(FfiPlatform::new());
    let gateway = AmtGateway::new(config, platform);

    to_handle(gateway)
}

/// Destroy an AMT Gateway
///
/// JNI signature: (J)V
#[no_mangle]
pub extern "system" fn Java_com_blockcast_amt_AmtGateway_nativeDestroy(
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
pub extern "system" fn Java_com_blockcast_amt_AmtGateway_nativeGetState(
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
pub extern "system" fn Java_com_blockcast_amt_AmtGateway_nativeGetRelayPort(
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
pub extern "system" fn Java_com_blockcast_amt_AmtGateway_nativeStartDiscovery<'local>(
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
pub extern "system" fn Java_com_blockcast_amt_AmtGateway_nativeHandleAdvertisement(
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
        AmtMessage::RelayAdvertisement {
            nonce,
            relay_address,
        } => match gw.handle_advertisement(nonce, relay_address) {
            Ok(()) => 0,
            Err(_) => -4,
        },
        _ => -5,
    }
}

/// Request membership
///
/// JNI signature: (JZ)[B
/// Returns encoded Request message or null on error
#[no_mangle]
pub extern "system" fn Java_com_blockcast_amt_AmtGateway_nativeRequestMembership<'local>(
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
pub extern "system" fn Java_com_blockcast_amt_AmtGateway_nativeHandleQuery<'local>(
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
        AmtMessage::MembershipQuery {
            request_nonce,
            response_mac,
            query_data,
            gateway_address,
        } => match gw.handle_query(request_nonce, response_mac, query_data, gateway_address) {
            Ok(data) => match env.byte_array_from_slice(&data) {
                Ok(arr) => arr.into_raw(),
                Err(_) => std::ptr::null_mut(),
            },
            Err(_) => std::ptr::null_mut(),
        },
        _ => std::ptr::null_mut(),
    }
}

/// Send membership update
///
/// JNI signature: (J[B)[B
/// Returns encoded MembershipUpdate message or null on error
#[no_mangle]
pub extern "system" fn Java_com_blockcast_amt_AmtGateway_nativeSendUpdate<'local>(
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
pub extern "system" fn Java_com_blockcast_amt_AmtGateway_nativeHandleData<'local>(
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
        AmtMessage::MulticastData { ip_packet } => match gw.handle_data(ip_packet) {
            Ok(packet) => match env.byte_array_from_slice(&packet) {
                Ok(arr) => arr.into_raw(),
                Err(_) => std::ptr::null_mut(),
            },
            Err(_) => std::ptr::null_mut(),
        },
        _ => std::ptr::null_mut(),
    }
}

/// Send teardown
///
/// JNI signature: (J)[B
/// Returns encoded Teardown message or null on error, including when the
/// relay never sent Gateway Address fields (no Teardown it could accept)
#[no_mangle]
pub extern "system" fn Java_com_blockcast_amt_AmtGateway_nativeSendTeardown<'local>(
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

/// Teardown owed after a Membership Query that reported a new gateway endpoint
///
/// JNI signature: (J)[B
/// Returns the encoded Teardown RFC 7450 §5.2.3.7.1 requires once the relay's
/// Query reports a gateway endpoint other than the one the last Membership
/// Update was sent from, or null when none is owed. Call after
/// nativeHandleQuery and before the nativeSendUpdate answering that Query,
/// and send the Teardown to the relay first. The gateway state is unchanged.
#[no_mangle]
pub extern "system" fn Java_com_blockcast_amt_AmtGateway_nativeRebindTeardown<'local>(
    env: JNIEnv<'local>,
    _class: JClass,
    handle: jlong,
) -> jbyteArray {
    if handle == 0 {
        return std::ptr::null_mut();
    }

    let gw = unsafe { from_handle(handle) };

    match gw.rebind_teardown() {
        Some(msg) => match env.byte_array_from_slice(&msg.encode()) {
            Ok(arr) => arr.into_raw(),
            Err(_) => std::ptr::null_mut(),
        },
        None => std::ptr::null_mut(),
    }
}

/// Reset gateway to idle state
///
/// JNI signature: (J)V
#[no_mangle]
pub extern "system" fn Java_com_blockcast_amt_AmtGateway_nativeReset(
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
pub extern "system" fn Java_com_blockcast_amt_Driad_nativeBuildQuery<'local>(
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

/// Build the DNS query for a source's AMTRELAY records (RFC 8777), with EDNS(0)
///
/// JNI signature: (Ljava/lang/String;I)[B
/// Returns the query message, or null when the source is not an IP literal
#[no_mangle]
pub extern "system" fn Java_com_blockcast_amt_Driad_nativeBuildDnsQuery<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass,
    source_address: JString,
    transaction_id: jint,
) -> jbyteArray {
    let addr_str: String = match env.get_string(&source_address) {
        Ok(s) => s.into(),
        Err(_) => return std::ptr::null_mut(),
    };

    let addr = match addr_str.parse() {
        Ok(a) => a,
        Err(_) => return std::ptr::null_mut(),
    };

    let query = crate::driad::DriadResolver::build_dns_query_edns(addr, transaction_id as u16);

    match env.byte_array_from_slice(&query) {
        Ok(arr) => arr.into_raw(),
        Err(_) => std::ptr::null_mut(),
    }
}

/// Pick a relay from the DNS answer to a query built by nativeBuildDnsQuery
///
/// JNI signature: ([B[B)Ljava/lang/String;
/// Returns the relay (IP literal or DNS name) of the lowest precedence, or null
/// when the answer does not match the query or has no usable AMTRELAY record
#[no_mangle]
pub extern "system" fn Java_com_blockcast_amt_Driad_nativeParseDnsResponse<'local>(
    env: JNIEnv<'local>,
    _class: JClass,
    query: JByteArray<'local>,
    response: JByteArray<'local>,
) -> jni::sys::jstring {
    let (Ok(query), Ok(response)) = (
        env.convert_byte_array(&query),
        env.convert_byte_array(&response),
    ) else {
        return std::ptr::null_mut();
    };

    let Some(relay) = crate::driad::DriadResolver::parse_dns_response_validated(&query, &response)
    else {
        return std::ptr::null_mut();
    };

    match env.new_string(relay.to_string()) {
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
pub extern "system" fn Java_com_blockcast_amt_IgmpSsm_nativeCreateJoinReport<'local>(
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
pub extern "system" fn Java_com_blockcast_amt_IgmpSsm_nativeCreateMultiJoinReport<'local>(
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
pub extern "system" fn Java_com_blockcast_amt_AmtGateway_nativeGetVersion<'local>(
    env: JNIEnv<'local>,
    _class: JClass,
) -> jni::sys::jstring {
    match env.new_string("0.1.0") {
        Ok(s) => s.into_raw(),
        Err(_) => std::ptr::null_mut(),
    }
}

// ============================================================================
// Legacy symbols for pim-multicast-gateway
// ============================================================================

// pim's packages/blockcast-sdk-android still declares these natives in package
// com.blockcast.sdk.amt and builds this crate from its submodule, so the old names
// must keep resolving. Remove once pim's AmtGateway moves to com.blockcast.amt;
// pim pins packages/amt-protocol at 61a16b3d. tests/jni_exports_test.sh asserts
// both name sets, so drop the legacy half there in the same change.
macro_rules! legacy_symbol {
    ($old:ident => $new:ident ($($arg:ident: $ty:ty),*) $(-> $ret:ty)?) => {
        #[no_mangle]
        pub extern "system" fn $old<'local>(
            env: JNIEnv<'local>,
            class: JClass<'local>,
            $($arg: $ty),*
        ) $(-> $ret)? {
            $new(env, class, $($arg),*)
        }
    };
}

legacy_symbol!(Java_com_blockcast_sdk_amt_AmtGateway_nativeCreate => Java_com_blockcast_amt_AmtGateway_nativeCreate(relay_address: JString<'local>, relay_port: jint) -> jlong);
legacy_symbol!(Java_com_blockcast_sdk_amt_AmtGateway_nativeDestroy => Java_com_blockcast_amt_AmtGateway_nativeDestroy(handle: jlong));
legacy_symbol!(Java_com_blockcast_sdk_amt_AmtGateway_nativeGetState => Java_com_blockcast_amt_AmtGateway_nativeGetState(handle: jlong) -> jint);
legacy_symbol!(Java_com_blockcast_sdk_amt_AmtGateway_nativeGetRelayPort => Java_com_blockcast_amt_AmtGateway_nativeGetRelayPort(handle: jlong) -> jint);
legacy_symbol!(Java_com_blockcast_sdk_amt_AmtGateway_nativeStartDiscovery => Java_com_blockcast_amt_AmtGateway_nativeStartDiscovery(handle: jlong) -> jbyteArray);
legacy_symbol!(Java_com_blockcast_sdk_amt_AmtGateway_nativeHandleAdvertisement => Java_com_blockcast_amt_AmtGateway_nativeHandleAdvertisement(handle: jlong, data: JByteArray<'local>) -> jint);
legacy_symbol!(Java_com_blockcast_sdk_amt_AmtGateway_nativeRequestMembership => Java_com_blockcast_amt_AmtGateway_nativeRequestMembership(handle: jlong, p_flag: jboolean) -> jbyteArray);
legacy_symbol!(Java_com_blockcast_sdk_amt_AmtGateway_nativeHandleQuery => Java_com_blockcast_amt_AmtGateway_nativeHandleQuery(handle: jlong, data: JByteArray<'local>) -> jbyteArray);
legacy_symbol!(Java_com_blockcast_sdk_amt_AmtGateway_nativeSendUpdate => Java_com_blockcast_amt_AmtGateway_nativeSendUpdate(handle: jlong, report_data: JByteArray<'local>) -> jbyteArray);
legacy_symbol!(Java_com_blockcast_sdk_amt_AmtGateway_nativeHandleData => Java_com_blockcast_amt_AmtGateway_nativeHandleData(handle: jlong, data: JByteArray<'local>) -> jbyteArray);
legacy_symbol!(Java_com_blockcast_sdk_amt_AmtGateway_nativeSendTeardown => Java_com_blockcast_amt_AmtGateway_nativeSendTeardown(handle: jlong) -> jbyteArray);
legacy_symbol!(Java_com_blockcast_sdk_amt_AmtGateway_nativeRebindTeardown => Java_com_blockcast_amt_AmtGateway_nativeRebindTeardown(handle: jlong) -> jbyteArray);
legacy_symbol!(Java_com_blockcast_sdk_amt_AmtGateway_nativeReset => Java_com_blockcast_amt_AmtGateway_nativeReset(handle: jlong));
legacy_symbol!(Java_com_blockcast_sdk_amt_AmtGateway_nativeGetVersion => Java_com_blockcast_amt_AmtGateway_nativeGetVersion() -> jni::sys::jstring);
legacy_symbol!(Java_com_blockcast_sdk_amt_Driad_nativeBuildQuery => Java_com_blockcast_amt_Driad_nativeBuildQuery(source_address: JString<'local>) -> jni::sys::jstring);
legacy_symbol!(Java_com_blockcast_sdk_amt_IgmpSsm_nativeCreateJoinReport => Java_com_blockcast_amt_IgmpSsm_nativeCreateJoinReport(source_address: JString<'local>, group_address: JString<'local>) -> jbyteArray);
legacy_symbol!(Java_com_blockcast_sdk_amt_IgmpSsm_nativeCreateMultiJoinReport => Java_com_blockcast_amt_IgmpSsm_nativeCreateMultiJoinReport(source_address: JString<'local>, group_addresses: JObjectArray<'local>) -> jbyteArray);
