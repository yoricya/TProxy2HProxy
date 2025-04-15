mod extractors;
mod forwards;

use async_std::net::{TcpListener, TcpStream};
use async_std::task;
use async_std::os::unix::io::{AsRawFd};
use async_std::io::{ReadExt, WriteExt};
use async_std::io::{self, Read, Write};

use std::time::{Instant};
use std::net::{SocketAddr};
use std::time::{SystemTime, UNIX_EPOCH};

use std::fs;
use toml::Value;

use crate::extractors::http_extract_domain;
use crate::extractors::tls_extract_domain;

use libc::{setsockopt, c_int, SOL_IP, IP_TRANSPARENT};

// use crate::forwards::create_http_proxy_header;


// Build as TARGET_CC=x86_64-unknown-linux-gnu cargo build --release --target x86_64-unknown-linux-gnu 

fn main(){
    let conf = read_config();


    if conf.is_verbose {
        println!("[I] Verbose mode enabled.");
    }


    task::block_on(async {
        let listener = TcpListener::bind(conf.tp_proxy_addr.clone()).await.unwrap_or_else(|err| {
            panic!("[E] Cannot start server: {err}");
        });


        let fd: i32 = listener.as_raw_fd();
        if conf.is_verbose {
            println!("[I] Server docket descriptor: {fd}");
        }


        // IP_TRANSPARENT для того чтобы сокет принимал прокси трафик 
        let option_value: c_int = 1;
        let result = unsafe {
            setsockopt(
                fd,
                SOL_IP,                  // Устанавливаем опцию на уровне IP
                IP_TRANSPARENT,           // Устанавливаем флаг IP_TRANSPARENT
                &option_value as *const _ as *const libc::c_void,
                std::mem::size_of_val(&option_value) as u32,
            )
        };
    
        if result < 0 {
            panic!("[E] cannot set IP_TRANSPARENT! Result code {result}");
        }


        // Сервер стартанул :P 
        println!("[S] Server started at {}", conf.tp_proxy_addr);

        while let Ok((stream, _addr)) = listener.accept().await {
            task::spawn(handle_client(stream, conf.clone()));
        }
    });
}

#[derive(Clone)]
struct TPForwarderConf {
    forward_to_http_proxy: Option<String>,
    tp_proxy_addr: SocketAddr,
    is_verbose: bool
}

fn read_config() -> TPForwarderConf { 
    let res_config_string = fs::read_to_string("conf.toml");

    let conf_string = if !res_config_string.is_ok() {
        let is = fs::write("conf.toml", "tp_addr = \"0.0.0.0:12345\"\nforward_to_http_proxy = \"127.0.0.1:8080\"");
        if !is.is_ok() {
            println!("[W] Cannot create config file.")
        }

        println!("[I] Config file created.");

        "tp_addr = \"0.0.0.0:12345\"\nforward_to_http_proxy = \"127.0.0.1:8080\"".to_string()
    } else {
        res_config_string.unwrap()
    };


    // Parse toml config
    let res_toml_conf: Result<Value, toml::de::Error> = toml::from_str(&conf_string);

    let toml_conf = if res_toml_conf.is_ok() {
        res_toml_conf.unwrap()
    } else {
        panic!("Can't read config file! {}", res_toml_conf.err().unwrap_or_else(|| {
            panic!("Can't read config file! Unknown error.");
        }));
    };


    // TP Address
    let tp_addr = if let Some(value) = toml_conf.get("tp_addr") {
        value.as_str().unwrap_or_else(||{
            println!("[W] Transparent proxy address defined incorrect! Set 'tp_addr = [address as string]' in conf file.");
            "0.0.0.0:12345"
        })
    } else {
        println!("[W] Transparent proxy address not defined! Set 'tp_addr = [address as string]' in conf file.");
        "0.0.0.0:12345"
    };


    // Forward address
    let forward_to_http_proxy = if let Some(value) = toml_conf.get("forward_to_http_proxy") {
        value.as_str().unwrap_or_else(||{
            println!("[W] Forward address defined incorrect! Set 'forward_to_http_proxy = [address as string]' in conf file.");
            "127.0.0.1:8080"
        })
    } else {
        println!("[W] Forward address not defined! Set 'forward_to_http_proxy = [address as string]' in conf file.");
        "127.0.0.1:8080"
    };
    

    // Is verbose 
    let is_verbose = if let Some(value) = toml_conf.get("is_verbose") {
        value.as_bool().unwrap_or_else(||{
            false
        })
    } else {false};


    // Parse TP-Proxy Address
    let res_addr = tp_addr.parse::<SocketAddr>();
    let addr = if res_addr.is_ok() {
        res_addr.unwrap()
    } else {
        panic!("[E] tp_addr is not valid ip address!")
    };


    return TPForwarderConf{
        forward_to_http_proxy: Some(forward_to_http_proxy.to_string()),
        tp_proxy_addr: addr,
        is_verbose: is_verbose
    }
}

async fn handle_client(mut stream: TcpStream, conf: TPForwarderConf) {

    // Only Verbose. Начало отсчета времени инициализции туннеля
    let t_start = if conf.is_verbose {
        Some(Instant::now())
    } else {None};


    // Извлекаем откуда и куда идет трафик
    let connect_from = stream.peer_addr().unwrap();
    let connect_to = stream.local_addr().unwrap();


    // Only Verbose. Создание хеша соединения для упрощения отладки
    let conn_hash = if conf.is_verbose {
        let hash = format!("{:x}", md5::compute(format!("{connect_to} {connect_from} {}", SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs_f64())));
       
        println!("[I] - ({hash}) New connect from: '{connect_from}' to '{connect_to}'");
        
        hash
    } else {"".to_string()};


    // Какая никакая, но всё таки попытка предотвратить зацикливание
    if (format!("{}", connect_to.ip()) == format!("{}", conf.tp_proxy_addr.ip()) || format!("{}", connect_to.ip()) == "127.0.0.1") && connect_to.port() == conf.tp_proxy_addr.port() {
        
        if conf.is_verbose {
            println!("[E] - ({conn_hash}) Loop detected!");
        }

        return;
    }


    // Читаем переданный клиентом хеадер
    let mut buff = [0u8; 8192];
    let received_bytes = stream.read(&mut buff).await.unwrap_or_else(|err| {

        if conf.is_verbose {
            println!("[W] - ({conn_hash}) Error while reading header from '{connect_from}', error: {err}");
        }

        return 0;
    });

    // If received 0 bytes -> maybe err
    if received_bytes == 0 {

        if conf.is_verbose {
            println!("[W] - ({conn_hash}) client received 0 bytes, maybe error.");
        }

        return;
    }


    // Извлекаем домен из хеадера
    let connect_to_port = connect_to.port();

    let mut domain_or_none = if connect_to_port == 80 { // HTTP Порт
        
        // Пробуем парсить как HTTP
        http_extract_domain(&(buff.clone())) 

    } else if connect_to_port == 443 { // TLS Порт

        // Пробуем парсить как TLS
        tls_extract_domain(&(buff.clone()))

    } else {
        None
    };

    // Если преимущественно по номеру порта не удалось извлечь домен - пробуем без учета номера порта
    if domain_or_none.is_none() {

        // Пробуем парсить как TLS трафик
        domain_or_none = tls_extract_domain(&(buff.clone()));

        // Не получилось?
        if domain_or_none.is_none() { 

            // Тогда пробуем парсить как HTTP
            domain_or_none = http_extract_domain(&(buff.clone()));

        }

    }


    // Get destination socket
    let mut destination_conn = if domain_or_none.is_none() {

        // Если домен извлечь не получилось


        if conf.is_verbose {
            println!("[W] - ({conn_hash}) Cannot extracting domain.");
        }


        // Открываем сокет напрямую с искомым ресурсом

        let res_destination_conn = TcpStream::connect(connect_to).await;
        
        if let Err(err) = res_destination_conn {

            if conf.is_verbose {
                println!("[W] - ({conn_hash}) Cannot connect to destination address, {}", err);
            }

            return;
        }
    

        res_destination_conn.unwrap()
    } else {

        // Если домен удалось извлечь


        let domain = domain_or_none.unwrap();

        if conf.is_verbose {
            println!("[I] - ({conn_hash}) Extracted domain: {domain}");
        }
    

        // Открываем сокет с прокси сервером

        let res_destination_conn = TcpStream::connect(conf.forward_to_http_proxy.unwrap()).await;
        
        if let Err(err) = res_destination_conn {

            if conf.is_verbose {
                println!("[W] - ({conn_hash}) Cannot connect to proxy, {err}");
            }

            return;
        }


        let mut destination_conn = res_destination_conn.unwrap();


        // Отправляем заголовки HTTP Proxy

        let http_proxy_header_str = format!("CONNECT {domain}:{connect_to_port} HTTP/1.1\r\nHost: {domain}:{connect_to_port}\r\nProxy-Connection: Keep-Alive\r\n\r\n");
        if let Err(err) = destination_conn.write(http_proxy_header_str.as_bytes()).await {
            
            if conf.is_verbose {
                println!("[W] - ({conn_hash}) Cannot write proxy headers {err}");
            }

            return;
        }

        let mut response_buf = [0; 512];
        let n_or_err = destination_conn.read(&mut response_buf).await;

        if let Err(err) = n_or_err {

            if conf.is_verbose {
                println!("[W] - ({conn_hash}) Cannot read proxy response {err}");
            }

            return;
        }


        // Читаем ответ

        let response = String::from_utf8_lossy(&response_buf[..n_or_err.unwrap()]).to_string();
        if !response.starts_with("HTTP/1.1 200") {
            
            if conf.is_verbose {
                let resp_err = if let Some(first_line) = response.split("\r\n").next() {
                    first_line
                } else {""};

                println!("[W] - ({conn_hash}) Cannot create proxy tunnel. Proxy returned unknown response. {resp_err}");
            }

            return;
        }

        destination_conn
    };


    if conf.is_verbose {
        println!("[I] - ({conn_hash}) Tunnel initialing success. Elapsed: {:.2?} micros", t_start.unwrap().elapsed().as_micros());
    }


    // Forward client header
    if let Err(err) = destination_conn.write(&buff[..received_bytes]).await {
        
        if conf.is_verbose {
            println!("[W] - ({conn_hash}) Cannot forward client header. {err}");
        }

        return
    } 


    // Я в душе не чаю как мне сделать нормальный пайп как в гошке через
    // go io.copy(conn, dest_conn)
    // io.copy(dest_conn, conn)
    //
    // Но вроде и так, через clone работает
    let mut destination_conn_clone = destination_conn.clone();
    let mut stream_clone = stream.clone();

    
    // go io.copy(conn, dest_conn)
    task::spawn(async move {
        io::copy(&mut stream_clone, &mut destination_conn_clone).await;
        destination_conn_clone.shutdown(std::net::Shutdown::Both);
    });


    // io.copy(dest_conn, conn)
    io::copy(&mut destination_conn, &mut stream).await;
}
