use super::{
    DeterministicNet, HeaderLimits, HeaderMap, HostNet, HttpRequestBuilder, HttpResponse,
    HttpResponseBuilder, HttpRetryPolicy, HttpRouter, HttpServerLimits, NetBackend, NetDecision,
    NetError, PollInterest, PollerEvent, RequestContext, SocketId, canonicalize_header_name,
    json_payload_encode, json_payload_new, json_payload_set_raw, json_payload_set_str,
    parse_http_request, post_json_payload, write_json_payload,
};

struct TestRouter;

impl HttpRouter for TestRouter {
    fn route(&self, req: &super::HttpRequest) -> HttpResponse {
        HttpResponse::ok(format!("{} {}", req.method, req.path))
    }
}

#[test]
fn deterministic_net_records_replay_decisions() {
        let mut backend = DeterministicNet::with_scripted_accepts(1);
        let listener = backend.bind("127.0.0.1:8080").expect("bind should work");
        backend.listen(listener, 128).expect("listen should work");
        let conn = backend
            .accept(listener)
            .expect("accept call should work")
            .expect("one scripted connection should exist");
        backend.push_read_chunk(conn, b"abc".to_vec());
        assert_eq!(backend.read(conn, 16).expect("read should work"), b"abc");
        assert_eq!(backend.write(conn, b"pong").expect("write should work"), 4);
        backend.close(conn).expect("close should work");

        let decisions = backend.decisions();
        assert!(matches!(decisions[0], NetDecision::Bind { .. }));
        assert!(matches!(
            decisions.last(),
            Some(NetDecision::Close { socket }) if *socket == conn
        ));
    }

    #[test]
    fn poller_queue_is_bounded() {
        let mut backend = DeterministicNet::default();
        let listener = backend.bind("127.0.0.1:9090").expect("bind should work");
        backend.listen(listener, 32).expect("listen should succeed");
        backend
            .poll_register(listener, PollInterest::Acceptable, 1)
            .expect("first registration should fit in queue");
        assert_eq!(
            backend.poll_register(listener, PollInterest::Readable, 1),
            Err(NetError::QueueFull)
        );
        assert_eq!(
            backend.poll_next(8).expect("poll should work"),
            vec![PollerEvent::Acceptable(listener)]
        );
    }

    #[test]
    fn host_poll_round_robins_registered_listeners() {
        let mut backend = HostNet::default();
        let first = backend.bind("127.0.0.1:0").expect("bind should work");
        backend.listen(first, 8).expect("listen should work");
        let second = backend.bind("127.0.0.1:0").expect("bind should work");
        backend.listen(second, 8).expect("listen should work");

        backend
            .poll_register(first, PollInterest::Acceptable, 8)
            .expect("first registration should work");
        backend
            .poll_register(second, PollInterest::Acceptable, 8)
            .expect("second registration should work");

        let first_events = backend.poll_next(1).expect("poll should work");
        let second_events = backend.poll_next(1).expect("poll should work");
        assert_eq!(first_events.len(), 1);
        assert_eq!(second_events.len(), 1);
        assert_ne!(first_events[0], second_events[0]);
    }

    #[test]
    fn request_context_deadline_and_cancel_are_enforced() {
        let mut backend = DeterministicNet::default();
        backend.register_context(RequestContext::new(super::ContextId(7), "req-7"));
        backend
            .set_deadline(super::ContextId(7), 20)
            .expect("deadline should work");
        backend
            .cancel(super::ContextId(7))
            .expect("cancel should work");
        let ctx = backend
            .contexts
            .get(&super::ContextId(7))
            .expect("context exists");
        assert_eq!(ctx.check(10), Err(NetError::Cancelled));
    }

    #[test]
    fn parse_http_request_parses_chunked_request_and_expect_continue() {
        let request = parse_http_request(
            b"POST /upload HTTP/1.1\r\nHost: example\r\nTransfer-Encoding: chunked\r\nExpect: 100-continue\r\n\r\n4\r\ntest\r\n0\r\n\r\n",
            &HttpServerLimits::default(),
        )
        .expect("request should parse");
        assert_eq!(request.method, "POST");
        assert_eq!(request.path, "/upload");
        assert_eq!(request.body, b"test");
    }

    #[test]
    fn http_serve_once_routes_request() {
        let mut backend = DeterministicNet::with_scripted_accepts(1);
        let listener = backend.bind("127.0.0.1:9191").expect("bind should work");
        backend.listen(listener, 64).expect("listen should work");
        let connection = SocketId(1);
        backend.push_read_chunk(
            connection,
            b"GET /ping HTTP/1.1\r\nHost: localhost\r\n\r\n".to_vec(),
        );

        let bytes = super::serve_http_once(
            &mut backend,
            listener,
            &TestRouter,
            &HttpServerLimits::default(),
        )
        .expect("serve should work");
        assert!(bytes > 0);
    }

    #[test]
    fn http_serve_persistent_once_handles_multiple_requests() {
        let mut backend = DeterministicNet::with_scripted_accepts(1);
        let listener = backend.bind("127.0.0.1:9292").expect("bind should work");
        backend.listen(listener, 64).expect("listen should work");
        let connection = SocketId(1);
        backend.push_read_chunk(
            connection,
            b"GET /a HTTP/1.1\r\nHost: localhost\r\nConnection: keep-alive\r\n\r\n".to_vec(),
        );
        backend.push_read_chunk(
            connection,
            b"GET /b HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n".to_vec(),
        );

        let bytes = super::serve_http_persistent_once(
            &mut backend,
            listener,
            &TestRouter,
            &HttpServerLimits::default(),
            8,
        )
        .expect("persistent serve should work");
        assert!(bytes > 0);
        assert!(
            backend
                .decisions()
                .iter()
                .any(|d| matches!(d, NetDecision::Close { socket } if *socket == connection))
        );
    }

    #[test]
    fn http_serve_connection_oneoff_closes_even_with_keepalive_request() {
        let mut backend = DeterministicNet::with_scripted_accepts(1);
        let listener = backend.bind("127.0.0.1:9393").expect("bind should work");
        backend.listen(listener, 64).expect("listen should work");
        let connection = backend
            .accept(listener)
            .expect("accept call should work")
            .expect("scripted connection should exist");
        backend.push_read_chunk(
            connection,
            b"GET /x HTTP/1.1\r\nHost: localhost\r\nConnection: keep-alive\r\n\r\n".to_vec(),
        );

        let bytes = super::serve_http_connection(
            &mut backend,
            connection,
            &TestRouter,
            &HttpServerLimits::default(),
            super::HttpConnectionMode::OneOff,
        )
        .expect("connection serve should work");
        assert!(bytes > 0);
        assert!(
            backend
                .decisions()
                .iter()
                .any(|d| matches!(d, NetDecision::Close { socket } if *socket == connection))
        );
    }

    #[test]
    fn deterministic_validates_addresses() {
        let mut backend = DeterministicNet::default();
        assert!(backend.bind("not-an-address").is_err());
        assert!(backend.connect("still-bad").is_err());
    }

    #[test]
    fn header_map_canonicalizes_and_bounds_entries() {
        let mut headers = HeaderMap::default();
        headers
            .insert(
                " Content-Type ",
                "application/json",
                HeaderLimits::default(),
            )
            .expect("insert should work");
        assert_eq!(headers.get("content-type"), Some("application/json"));
        assert!(canonicalize_header_name("X-Trace").is_ok());
        assert!(canonicalize_header_name("").is_err());
    }

    #[test]
    fn request_and_response_builders_validate_limits() {
        let limits = HttpServerLimits {
            max_body_bytes: 4,
            ..HttpServerLimits::default()
        };
        let req = HttpRequestBuilder::default()
            .method("POST")
            .path("/v1/items")
            .body(b"1234".to_vec())
            .build(&limits)
            .expect("request should build");
        assert_eq!(req.path, "/v1/items");

        let err = HttpResponseBuilder::default()
            .status(200, "OK")
            .body(b"12345".to_vec())
            .build(&limits)
            .expect_err("response should fail size limit");
        assert!(matches!(err, NetError::LimitsExceeded(_)));
    }

    #[test]
    fn retry_policy_backoff_is_deterministic() {
        let policy = HttpRetryPolicy {
            max_attempts: 3,
            initial_backoff_ms: 10,
            max_backoff_ms: 25,
            factor: 2,
        };
        policy.validate().expect("policy should be valid");
        assert_eq!(policy.backoff_for_attempt(1), Some(10));
        assert_eq!(policy.backoff_for_attempt(2), Some(20));
        assert_eq!(policy.backoff_for_attempt(3), Some(25));
        assert_eq!(policy.backoff_for_attempt(4), None);
    }

    #[test]
    fn json_payload_helpers_encode_and_validate_raw_values() {
        let mut payload = json_payload_new();
        json_payload_set_str(&mut payload, "component", "stdlib.http")
            .expect("set_str should work");
        json_payload_set_raw(&mut payload, "ok", "true").expect("set_raw should work");
        json_payload_set_raw(&mut payload, "count", "3").expect("set_raw should work");
        let encoded = json_payload_encode(&payload).expect("encode should work");
        assert_eq!(
            encoded,
            r#"{"component":"stdlib.http","count":3,"ok":true}"#
        );

        let err = json_payload_set_raw(&mut payload, "broken", "{")
            .expect_err("invalid raw json should fail");
        assert!(matches!(err, NetError::Parse(message) if message.contains("payload.broken")));
    }

    #[test]
    fn write_json_payload_uses_canonical_response_builder_path() {
        let mut payload = json_payload_new();
        json_payload_set_str(&mut payload, "status", "ok").expect("set should work");
        let response = write_json_payload(200, "OK", &payload, true, &HttpServerLimits::default())
            .expect("json response should build");
        assert_eq!(response.status, 200);
        assert_eq!(
            response.headers.get("content-type").map(String::as_str),
            Some("application/json")
        );
        assert_eq!(response.body, br#"{"status":"ok"}"#);
    }

    #[test]
    fn post_json_payload_uses_canonical_request_builder_path() {
        let mut payload = json_payload_new();
        json_payload_set_str(&mut payload, "type", "ping").expect("set should work");
        let request = post_json_payload("/v1/events", &payload, true, &HttpServerLimits::default())
            .expect("json request should build");
        assert_eq!(request.method, "POST");
        assert_eq!(request.path, "/v1/events");
        assert_eq!(
            request.headers.get("content-type").map(String::as_str),
            Some("application/json")
        );
        assert_eq!(request.body, br#"{"type":"ping"}"#);
}
