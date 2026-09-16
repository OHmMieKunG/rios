//! Bounded one-request HTTP/1.1 responder; no OS sockets, filesystem or wall clock.
const MAX_HEADER: usize = 8192;

pub(super) fn response(input: &[u8], body: &str) -> Option<Vec<u8>> {
    let end = input.windows(4).position(|w| w == b"\r\n\r\n");
    if input.len() > MAX_HEADER && end.is_none_or(|end| end + 4 > MAX_HEADER) {
        return Some(reply("431 Request Header Fields Too Large", "", false));
    }
    let end = end?;
    let Ok(header) = std::str::from_utf8(&input[..end]) else {
        return Some(reply("400 Bad Request", "", false));
    };
    let mut lines = header.split("\r\n");
    let parts: Vec<_> = lines.next().unwrap_or("").split(' ').collect();
    if parts.len() != 3 || !matches!(parts[2], "HTTP/1.0" | "HTTP/1.1") {
        return Some(reply("400 Bad Request", "", false));
    }
    let mut hosts = 0;
    let mut lengths = 0;
    for line in lines {
        let Some((name, value)) = line.split_once(':') else {
            return Some(reply("400 Bad Request", "", false));
        };
        if name.is_empty()
            || !name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b))
            || value.bytes().any(|b| b < 32 && b != b'\t' || b == 127)
        {
            return Some(reply("400 Bad Request", "", false));
        }
        if name.eq_ignore_ascii_case("host") {
            hosts += 1;
            if value.trim().is_empty() {
                return Some(reply("400 Bad Request", "", false));
            }
        }
        if name.eq_ignore_ascii_case("content-length") {
            lengths += 1;
            if value.trim() != "0" || lengths > 1 {
                return Some(reply("400 Bad Request", "", false));
            }
        }
        if name.eq_ignore_ascii_case("transfer-encoding") {
            return Some(reply("400 Bad Request", "", false));
        }
    }
    if hosts > 1 || parts[2] == "HTTP/1.1" && hosts != 1 {
        return Some(reply("400 Bad Request", "", false));
    }
    let head = parts[0] == "HEAD";
    Some(if !matches!(parts[0], "GET" | "HEAD") {
        reply("405 Method Not Allowed", "", head)
    } else if parts[1] != "/" {
        reply("404 Not Found", "", head)
    } else {
        reply("200 OK", body, head)
    })
}
fn reply(status: &str, body: &str, head: bool) -> Vec<u8> {
    let mut response = format!("HTTP/1.1 {status}\r\nContent-Length: {}\r\nContent-Type: text/plain; charset=utf-8\r\nConnection: close\r\n{}\r\n", body.len(), if status.starts_with("405") { "Allow: GET, HEAD\r\n" } else { "" }).into_bytes();
    if !head {
        response.extend_from_slice(body.as_bytes());
    }
    response
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn bounded_fragmented_requests_and_strict_framing() {
        assert!(response(b"GET / HTTP/1.1\r\nHost: lab\r\n", "hello").is_none());
        let text =
            String::from_utf8(response(b"HEAD / HTTP/1.1\r\nHost: lab\r\n\r\n", "hello").unwrap())
                .unwrap();
        assert!(text.contains("Content-Length: 5"));
        assert!(!text.ends_with("hello"));
        for request in [
            "GET / HTTP/1.1\r\n\r\n",
            "GET / HTTP/1.1\r\nHost: a\r\nHost: b\r\n\r\n",
            "GET / HTTP/1.0\r\nTransfer-Encoding: chunked\r\n\r\n",
            "GET / HTTP/1.0\r\nContent-Length: 2\r\n\r\n",
        ] {
            assert!(
                response(request.as_bytes(), "hello")
                    .unwrap()
                    .starts_with(b"HTTP/1.1 400")
            );
        }
        assert!(
            response(&vec![b'A'; 8193], "")
                .unwrap()
                .starts_with(b"HTTP/1.1 431")
        );
        for len in 0..256 {
            let _ = response(&vec![0xff; len], "");
        }
    }
}
