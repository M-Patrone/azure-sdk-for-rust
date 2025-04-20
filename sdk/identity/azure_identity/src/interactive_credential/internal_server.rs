use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::process::Output;
use std::time::Duration;
use tracing::{error, info};

///The port where the local server is listening on the auth_code
#[allow(dead_code)]
pub const LOCAL_SERVER_PORT: u16 = 47828;

#[derive(Debug)]
pub struct TokenPair {
    pub auth_code: String,
    pub id_token: String,
}

/// Opens the given URL in the default system browser and starts a local web server
/// to receive the authorization code.
#[allow(dead_code)]
#[cfg(target_os = "windows")]
pub async fn open_url(url: &str) -> Option<TokenPair> {
    use azure_core::process::{new_executor, Executor};
    use std::{ffi::OsStr, sync::Arc};

    let executor: Arc<dyn Executor> = new_executor();

    let command_ostr = OsStr::new("/C explorer");

    let args: &[&OsStr] = &[OsStr::new(url)];

    let spawned = executor.run(command_ostr, args).await;

    match spawned {
        Ok(spawned_ok) => {
            //Could open the browser
            if spawned_ok.stdout.len() > 0 && spawned_ok.stderr.len() == 0 {
                return handle_browser_command(spawned_ok);
            }
        }
        Err(e) => {
            error!("Failed to start browser command: {e}");
        }
    }
    info!("Open the following link manually in your browser: {url}");
    None
}

/// Opens the given URL in the default system browser and starts a local web server
/// to receive the authorization code.
#[allow(dead_code)]
#[cfg(target_os = "macos")]
pub async fn open_url(url: &str) -> Option<TokenPair> {
    use azure_core::process::{new_executor, Executor};
    use std::{ffi::OsStr, sync::Arc};

    let executor: Arc<dyn Executor> = new_executor();

    let command_ostr = OsStr::new("open");

    let args: &[&OsStr] = &[OsStr::new(url)];

    let spawned = executor.run(command_ostr, args).await;

    match spawned {
        Ok(spawned_ok) => {
            //Could open the browser
            if spawned_ok.stdout.len() > 0 && spawned_ok.stderr.len() == 0 {
                return handle_browser_command(spawned_ok);
            }
        }
        Err(e) => {
            error!("Failed to start browser command: {e}");
        }
    }
    info!("Open the following link manually in your browser: {url}");
    None
}

/// Opens the given URL in the default system browser and starts a local web server
/// to receive the authorization code.
#[allow(dead_code)]
#[cfg(target_os = "linux")]
pub async fn open_url(url: &str) -> Option<TokenPair> {
    use azure_core::process::{new_executor, Executor};
    use std::{ffi::OsStr, sync::Arc};

    info!("only authorize url: {}", url.clone());

    let executor: Arc<dyn Executor> = new_executor();
    if let Some(command) = find_linux_browser_command().await {
        let command_ostr = OsStr::new(&command);
        let args: &[&OsStr] = &[OsStr::new(url)];

        let spawned = executor.run(command_ostr, args).await;

        match spawned {
            Ok(spawned_ok) => {
                //Could not open the browser
                if spawned_ok.stdout.len() == 0 && spawned_ok.stderr.len() > 0 {
                    info!("Open the following link manually in your browser: {url}");
                }
                return handle_browser_command(spawned_ok);
            }
            Err(e) => {
                info!("Open the following link manually in your browser: {url}");
                error!("Failed to start browser command: {e}");
            }
        }
    }

    info!("Open the following link manually in your browser: {url}");
    None
}

/// Method to check if the command to open the link in a browser is available on the computer
/// exists.
#[allow(dead_code)]
#[cfg(target_os = "linux")]
async fn is_command_available(cmd: &str) -> bool {
    use azure_core::process::{new_executor, Executor};
    use std::{ffi::OsStr, sync::Arc};

    let executor: Arc<dyn Executor> = new_executor();
    let command_ostr = OsStr::new("which");

    let args: &[&OsStr] = &[OsStr::new(cmd)];

    executor
        .run(command_ostr, args)
        .await
        .map(|o| !o.stdout.is_empty())
        .unwrap_or(false)
}

/// Method with all the commands which could open the browser to call the authorization url
/// If there is no command installed or available on the system, it returns a 'None' and the link
/// will be logged
#[allow(dead_code)]
#[cfg(target_os = "linux")]
async fn find_linux_browser_command() -> Option<String> {
    let candidates = [
        "xdg-open",
        "gnome-open",
        "kfmclient",
        "microsoft-edge",
        "wslview",
    ];
    for cmd in candidates.iter() {
        if is_command_available(cmd).await {
            return Some(cmd.to_string());
        }
    }
    None
}

/// starting the browser if the browser could be started, then the webserver should be started to
/// get the auth code
#[allow(dead_code)]
fn handle_browser_command(result: Output) -> Option<TokenPair> {
    start_webserver()
}

/// Starts the webserver on the `http://localhost`. Returns None, if the server could not have
/// started
#[allow(dead_code)]
/// Starts a simple HTTP server on localhost to receive the auth code.
fn start_webserver() -> Option<TokenPair> {
    info!("starting webserver");
    let res = TcpListener::bind(("127.0.0.1", LOCAL_SERVER_PORT))
        .ok()
        .and_then(handle_tcp_connection);
    info!("ending webserver, {:#?}", res);
    res
}

fn handle_tcp_connection(listener: TcpListener) -> Option<TokenPair> {
    info!("HANDLING TCP CONNECTION");
    listener
        .incoming()
        .take(1)
        .next()?
        .ok()
        .and_then(handle_client)
}
/// Main method to handle the incoming traffic.
/// After a 10s timeout the stream will be closed
/// if the stream could be opened, we read the whole request and try to extract the auth_code
/// Returns also the html code to show if it worked
#[allow(dead_code)]
fn handle_client(mut stream: TcpStream) -> Option<TokenPair> {
    info!("HANDLING CLIENT");
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .ok()?;

    info!("after stream opening");

    let mut buf_reader = BufReader::new(&stream);
    let mut headers = String::new();
    let mut content_length: usize = 0;

    // Header lesen
    loop {
        let mut line = String::new();
        let bytes_read = buf_reader.read_line(&mut line).ok()?;
        if bytes_read == 0 {
            info!("Connection closed by client.");
            break;
        }

        //end of headers
        if line == "\r\n" {
            break;
        }

        if let Some(cl) = line.strip_prefix("Content-Length:") {
            content_length = cl.trim().parse().unwrap_or(0);
        }

        headers.push_str(&line);
    }

    let mut body = vec![0; content_length];
    buf_reader.read_exact(&mut body).ok()?;
    let body_str = String::from_utf8_lossy(&body);

    info!("Full request headers:\n{}", headers);
    info!("Full request body:\n{}", body_str);

    let res_auth = extract_auth_information(&body_str);

    let response_body = r#"<!DOCTYPE html>
<html><head><title>Auth Complete</title></head>
<body><p>Authentication complete. You may close this tab.</p></body>
</html>"#;

    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\n\r\n{}",
        response_body.len(),
        response_body
    );

    stream.write_all(response.as_bytes()).ok()?;
    stream.flush().ok()?;
    stream.shutdown(Shutdown::Both).ok()?;

    res_auth
}

fn extract_auth_information(body_str: &str) -> Option<TokenPair> {
    let parsed: std::collections::HashMap<_, _> = url::form_urlencoded::parse(body_str.as_bytes())
        .into_owned()
        .collect();

    let code = parsed.get("code").cloned();
    let id_token = parsed.get("id_token").cloned();
    let token_pair: Option<TokenPair> = match (code, id_token) {
        (Some(auth_code), Some(id_token)) => Some(TokenPair {
            id_token,
            auth_code,
        }),
        _ => None,
    };

    info!("token_pair information: {:#?}", token_pair);
    token_pair
}

/// Extracts the `code` query parameter from the request.
#[allow(dead_code)]
fn extract_auth_code(request: &str) -> Option<String> {
    info!("output full request: {:#?}", request);
    let code_start = request.rfind("code=")? + 5;
    let rest = &request[code_start..];
    let end = rest.find('&').unwrap_or(rest.len());
    Some(rest[..end].to_string())
}

#[cfg(test)]
mod test_internal_server {
    use super::*;
    use tracing::debug;
    use tracing::Level;
    use tracing_subscriber::FmtSubscriber;
    fn init_logger() {
        let subscriber = FmtSubscriber::builder()
            .with_max_level(Level::DEBUG)
            .finish();
        let _ = tracing::subscriber::set_global_default(subscriber);
    }

    #[tokio::test]
    async fn test_valid_command() {
        init_logger();
        assert!(is_command_available("ls").await);
    }

    #[tokio::test]
    async fn test_invalid_command() {
        init_logger();
        assert!(!is_command_available("non_existing_command_foo").await);
    }

    #[test]
    fn test_extract_code_param() {
        let url = "GET /?code=abc123&state=xyz";
        assert_eq!(extract_auth_code(url).unwrap(), "abc123");
    }

    #[test]
    fn test_extract_code_at_end() {
        let url = "GET /?state=xyz&code=abc123";
        assert_eq!(extract_auth_code(url).unwrap(), "abc123");
    }

    #[test]
    fn test_extract_code_missing() {
        let url = "GET /?state=only";
        assert!(extract_auth_code(url).is_none());
    }
}
