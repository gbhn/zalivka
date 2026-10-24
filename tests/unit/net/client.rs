use super::*;
use std::{
    io::{BufRead, BufReader, Write},
    net::TcpListener,
    thread,
    time::Duration,
};

#[test]
fn cloned_asset_clients_reuse_connections_and_consume_each_response() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let server = thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let mut stream = BufReader::new(stream);
        for path in ["first", "second"] {
            let mut line = String::new();
            stream.read_line(&mut line).unwrap();
            assert_eq!(line, format!("GET /{path} HTTP/1.1\r\n"));
            loop {
                line.clear();
                assert!(stream.read_line(&mut line).unwrap() > 0);
                if line == "\r\n" {
                    break;
                }
            }
            write!(
                stream.get_mut(),
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{path}",
                path.len()
            )
            .unwrap();
        }
    });
    let client = AssetClient::default();
    for (client, path) in [(client.clone(), "first"), (client, "second")] {
        // Only the fixture bypasses Apple URL validation and host proxy settings.
        let request = Request::get(format!("http://{address}/{path}"))
            .body(Vec::new())
            .unwrap();
        let response = crate::net::send_http_via(&client.agent, &request, None).unwrap();
        let reply = asset_reply(response, false).unwrap();
        assert_eq!(
            wire::get(&reply, &["ResponseBody"])
                .unwrap()
                .as_data()
                .unwrap(),
            path.as_bytes()
        );
    }
    server.join().unwrap();
}
