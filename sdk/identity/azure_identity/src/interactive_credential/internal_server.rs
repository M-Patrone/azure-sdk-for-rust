use base64::engine::general_purpose;
use base64::Engine;
use std::process::Output;
use std::time::Duration;
use tracing::{error, info};

use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
///The port where the local server is listening on the auth_code
#[allow(dead_code)]
pub const LOCAL_SERVER_PORT: u16 = 53298;
///saves the id_token most important claim to enable caching and also to check the `nonce`
#[derive(Debug)]
pub struct HybridAuthContext {
    pub auth_code: String,
    pub raw_id_token: String,
    pub oid_sub: String,
    pub tid: String,
    pub nonce: String,
}
/// Opens the given URL in the default system browser and starts a local web server
/// to receive the authorization code.
#[allow(dead_code)]
#[cfg(target_os = "linux")]
pub async fn open_url(url: &str) -> Option<HybridAuthContext> {
    use azure_core::process::{new_executor, Executor};
    use std::{ffi::OsStr, sync::Arc};

    info!("only authorize url: {}", url.clone());

    let executor: Arc<dyn Executor> = new_executor();
    if let Some(command) = find_linux_browser_command().await {
        let command_ostr = OsStr::new(&command);
        let args: &[&OsStr] = &[OsStr::new(url)];

        //TODO: remove debug to manually open url
        //let spawned = executor.run(command_ostr, args).await;
        let spawned: Result<Output, &str> = Err("DEBUG ERRROR");
        match spawned {
            Ok(spawned_ok) => {
                //Could not open the browser
                if spawned_ok.stdout.len() == 0 && spawned_ok.stderr.len() > 0 {
                    info!("Open the following link manually in your browser: {url}");
                }
            }
            Err(e) => {
                info!("Open the following link manually in your browser: {url}");
                error!("Failed to start browser command: {e}");
            }
        }

        return handle_browser_command();
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
fn handle_browser_command() -> Option<HybridAuthContext> {
    start_webserver()
}

/// Starts the webserver on the `http://localhost`. Returns None, if the server could not have
/// started
#[allow(dead_code)]
/// Starts a simple HTTP server on localhost to receive the auth code.
fn start_webserver() -> Option<HybridAuthContext> {
    info!("starting webserver");
    let res = TcpListener::bind(("127.0.0.1", LOCAL_SERVER_PORT))
        .ok()
        .and_then(handle_tcp_connection);
    info!("ending webserver, {:#?}", res);
    res
}

fn handle_tcp_connection(listener: TcpListener) -> Option<HybridAuthContext> {
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
fn handle_client(mut stream: TcpStream) -> Option<HybridAuthContext> {
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

    //let res_auth = extract_auth_information(&body_str);

    let code = extract_auth_code(&body_str);

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

    Some(HybridAuthContext {
        auth_code: code.unwrap_or(String::from("NO VALUE")),
        raw_id_token: String::from(""),
        nonce: String::from(""),
        oid_sub: String::from(""),
        tid: String::from(""),
    })
}
///method to decode the `id_token`
///
///pass the `id_token` and the search property
fn decode_id_token(id_token_encoded: &str, search_property: &str) -> Option<String> {
    let parts: Vec<&str> = id_token_encoded.split('.').collect();

    //decode base64
    let id_token_decoded = general_purpose::URL_SAFE_NO_PAD.decode(parts[1]).ok()?;

    let id_token_json: serde_json::Value = serde_json::from_slice(&id_token_decoded).ok()?;

    let id_token_decoded_val = id_token_json[search_property].as_str();
    info!(
        "searched value {} with value {:#?}",
        &search_property, id_token_decoded_val
    );

    id_token_decoded_val.map(|s| s.to_string())
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
