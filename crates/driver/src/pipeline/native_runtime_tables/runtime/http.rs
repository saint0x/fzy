use super::*;

pub(crate) const IMPORTS: &[NativeRuntimeImport] = &[
    NativeRuntimeImport {
        callee: "http.bind",
        symbol: "fz_native_net_bind",
        arity: 1,
    },
    NativeRuntimeImport {
        callee: "http.listen",
        symbol: "fz_native_net_listen",
        arity: 1,
    },
    NativeRuntimeImport {
        callee: "http.accept",
        symbol: "fz_native_net_accept",
        arity: 0,
    },
    NativeRuntimeImport {
        callee: "http.read",
        symbol: "fz_native_net_read",
        arity: 1,
    },
    NativeRuntimeImport {
        callee: "http.read_headers",
        symbol: "fz_native_net_read_headers",
        arity: 1,
    },
    NativeRuntimeImport {
        callee: "http.post_json",
        symbol: "fz_native_http_post_json",
        arity: 2,
    },
    NativeRuntimeImport {
        callee: "http.post_json_capture",
        symbol: "fz_native_http_post_json_capture",
        arity: 2,
    },
    NativeRuntimeImport {
        callee: "http.post_json_stream",
        symbol: "fz_native_http_post_json_stream",
        arity: 2,
    },
    NativeRuntimeImport {
        callee: "http.request_stream",
        symbol: "fz_native_http_request_stream",
        arity: 3,
    },
    NativeRuntimeImport {
        callee: "http.stream_read",
        symbol: "fz_native_http_stream_read",
        arity: 2,
    },
    NativeRuntimeImport {
        callee: "http.stream_read_line",
        symbol: "fz_native_http_stream_read_line",
        arity: 1,
    },
    NativeRuntimeImport {
        callee: "http.stream_eof",
        symbol: "fz_native_http_stream_eof",
        arity: 1,
    },
    NativeRuntimeImport {
        callee: "http.stream_status",
        symbol: "fz_native_http_stream_status",
        arity: 1,
    },
    NativeRuntimeImport {
        callee: "http.stream_error",
        symbol: "fz_native_http_stream_error",
        arity: 1,
    },
    NativeRuntimeImport {
        callee: "http.stream_close",
        symbol: "fz_native_http_stream_close",
        arity: 1,
    },
    NativeRuntimeImport {
        callee: "http.header_set",
        symbol: "fz_native_http_header",
        arity: 2,
    },
    NativeRuntimeImport {
        callee: "http.last_status",
        symbol: "fz_native_http_last_status",
        arity: 0,
    },
    NativeRuntimeImport {
        callee: "http.last_error",
        symbol: "fz_native_http_last_error",
        arity: 0,
    },
    NativeRuntimeImport {
        callee: "http.method",
        symbol: "fz_native_net_method",
        arity: 1,
    },
    NativeRuntimeImport {
        callee: "http.path",
        symbol: "fz_native_net_path",
        arity: 1,
    },
    NativeRuntimeImport {
        callee: "http.body",
        symbol: "fz_native_net_body",
        arity: 1,
    },
    NativeRuntimeImport {
        callee: "http.body_read",
        symbol: "fz_native_net_body_read",
        arity: 2,
    },
    NativeRuntimeImport {
        callee: "http.body_eof",
        symbol: "fz_native_net_body_eof",
        arity: 1,
    },
    NativeRuntimeImport {
        callee: "http.body_discard",
        symbol: "fz_native_net_body_discard",
        arity: 1,
    },
    NativeRuntimeImport {
        callee: "http.body_json",
        symbol: "fz_native_net_body_json",
        arity: 1,
    },
    NativeRuntimeImport {
        callee: "http.body_bind",
        symbol: "fz_native_net_body_bind",
        arity: 1,
    },
    NativeRuntimeImport {
        callee: "http.header",
        symbol: "fz_native_net_header",
        arity: 2,
    },
    NativeRuntimeImport {
        callee: "http.query",
        symbol: "fz_native_net_query",
        arity: 2,
    },
    NativeRuntimeImport {
        callee: "http.param",
        symbol: "fz_native_net_param",
        arity: 2,
    },
    NativeRuntimeImport {
        callee: "http.headers",
        symbol: "fz_native_net_headers",
        arity: 1,
    },
    NativeRuntimeImport {
        callee: "http.request_id",
        symbol: "fz_native_net_request_id",
        arity: 1,
    },
    NativeRuntimeImport {
        callee: "http.remote_addr",
        symbol: "fz_native_net_remote_addr",
        arity: 1,
    },
    NativeRuntimeImport {
        callee: "http.response_header_set",
        symbol: "fz_native_net_response_header_set",
        arity: 3,
    },
    NativeRuntimeImport {
        callee: "http.response_header_add",
        symbol: "fz_native_net_response_header_add",
        arity: 3,
    },
    NativeRuntimeImport {
        callee: "http.response_header_clear",
        symbol: "fz_native_net_response_header_clear",
        arity: 1,
    },
    NativeRuntimeImport {
        callee: "http.write",
        symbol: "fz_native_net_write",
        arity: 3,
    },
    NativeRuntimeImport {
        callee: "http.write_json",
        symbol: "fz_native_net_write_json",
        arity: 3,
    },
    NativeRuntimeImport {
        callee: "http.write_response",
        symbol: "fz_native_net_write_response",
        arity: 5,
    },
    NativeRuntimeImport {
        callee: "http.websocket_accept",
        symbol: "fz_native_net_websocket_accept",
        arity: 1,
    },
    NativeRuntimeImport {
        callee: "http.websocket_read",
        symbol: "fz_native_net_websocket_read",
        arity: 2,
    },
    NativeRuntimeImport {
        callee: "http.websocket_kind",
        symbol: "fz_native_net_websocket_kind",
        arity: 1,
    },
    NativeRuntimeImport {
        callee: "http.websocket_close_code",
        symbol: "fz_native_net_websocket_close_code",
        arity: 1,
    },
    NativeRuntimeImport {
        callee: "http.websocket_error",
        symbol: "fz_native_net_websocket_error",
        arity: 1,
    },
    NativeRuntimeImport {
        callee: "http.websocket_write_text",
        symbol: "fz_native_net_websocket_write_text",
        arity: 2,
    },
    NativeRuntimeImport {
        callee: "http.websocket_write_binary",
        symbol: "fz_native_net_websocket_write_binary",
        arity: 2,
    },
    NativeRuntimeImport {
        callee: "http.websocket_ping",
        symbol: "fz_native_net_websocket_ping",
        arity: 2,
    },
    NativeRuntimeImport {
        callee: "http.websocket_pong",
        symbol: "fz_native_net_websocket_pong",
        arity: 2,
    },
    NativeRuntimeImport {
        callee: "http.websocket_close",
        symbol: "fz_native_net_websocket_close",
        arity: 3,
    },
    NativeRuntimeImport {
        callee: "http.close",
        symbol: "fz_native_close",
        arity: 1,
    },
    NativeRuntimeImport {
        callee: "http.poll_next",
        symbol: "fz_native_net_poll_next",
        arity: 0,
    },
    NativeRuntimeImport {
        callee: "http.poll_register",
        symbol: "fz_native_net_poll_register",
        arity: 1,
    },
    NativeRuntimeImport {
        callee: "route.match",
        symbol: "fz_native_route_match",
        arity: 3,
    },
    NativeRuntimeImport {
        callee: "route.write_404",
        symbol: "fz_native_route_write_404",
        arity: 1,
    },
    NativeRuntimeImport {
        callee: "route.write_405",
        symbol: "fz_native_route_write_405",
        arity: 1,
    },
];
