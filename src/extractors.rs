pub fn http_extract_domain(header: &[u8]) -> Option<String> { 
    
    let mut i = 0;
    let header_len = header.len();
    while i < header_len {
        if i + 5 >= header_len {
            break;
        }

        let value = std::str::from_utf8(&header[i..i + 5]);
        if value.is_ok() && value.unwrap().to_lowercase() == "host:" {
            i += 5;

            let start_at = i;

            while i < header_len {

                if header[i] == b'\n' {
                    let domain = std::str::from_utf8(&header[start_at..i]);
                    if domain.is_err() {
                        return None;
                    }

                    return Some(domain.unwrap().trim().to_string());
                }

                i += 1;
            }
        }

        i += 1;
    }

    return None
}


// Всё что ниже писал GPT, я в душе не чаю как устроен TLS Handshake
pub fn tls_extract_domain(tls_data: &[u8]) -> Option<String> {
    // Проверка минимальной длины TLS-записи
    if tls_data.len() < 5 {
        return None;
    }

    // Проверка, является ли это TLS-рукопожатием (record type 0x16)
    if tls_data[0] != 0x16 {
        return None;
    }

    // Проверяем версию TLS из заголовка записи
    let tls_version = ((tls_data[1] as u16) << 8) | (tls_data[2] as u16);
    // Поддерживаем версии: 0x0301 (TLS 1.0), 0x0302 (TLS 1.1), 0x0303 (TLS 1.2/1.3)
    if tls_version != 0x0301 && tls_version != 0x0302 && tls_version != 0x0303 {
        return None;
    }

    // Получаем длину записи
    let record_length = ((tls_data[3] as usize) << 8) | (tls_data[4] as usize);
    if record_length + 5 > tls_data.len() {
        return None;
    }

    // Указатель на текущую позицию в данных
    let mut pos = 5;
    
    // Проверяем тип рукопожатия (должен быть ClientHello = 1)
    if pos >= tls_data.len() || tls_data[pos] != 0x01 {
        return None;
    }
    
    // Пропускаем тип рукопожатия (1 байт)
    pos += 1;
    
    // Проверяем, достаточно ли данных для длины рукопожатия (3 байта)
    if pos + 3 > tls_data.len() {
        return None;
    }
    
    // Получаем длину данных ClientHello
    let handshake_length = ((tls_data[pos] as usize) << 16) | 
                           ((tls_data[pos + 1] as usize) << 8) | 
                           (tls_data[pos + 2] as usize);
    pos += 3;
    
    if pos + handshake_length > tls_data.len() {
        return None;
    }
    
    // Запоминаем конец данных ClientHello
    let handshake_end = pos + handshake_length;
    
    // Пропускаем версию TLS клиента (2 байта)
    if pos + 2 > handshake_end {
        return None;
    }
    pos += 2;
    
    // Пропускаем random (32 байта)
    if pos + 32 > handshake_end {
        return None;
    }
    pos += 32;
    
    // Пропускаем session ID
    if pos + 1 > handshake_end {
        return None;
    }
    let session_id_length = tls_data[pos] as usize;
    pos += 1;
    
    if pos + session_id_length > handshake_end {
        return None;
    }
    pos += session_id_length;
    
    // Пропускаем список шифров (cipher suites)
    if pos + 2 > handshake_end {
        return None;
    }
    let cipher_suites_length = ((tls_data[pos] as usize) << 8) | (tls_data[pos + 1] as usize);
    pos += 2;
    
    if pos + cipher_suites_length > handshake_end {
        return None;
    }
    pos += cipher_suites_length;
    
    // Пропускаем методы сжатия
    if pos + 1 > handshake_end {
        return None;
    }
    let compression_methods_length = tls_data[pos] as usize;
    pos += 1;
    
    if pos + compression_methods_length > handshake_end {
        return None;
    }
    pos += compression_methods_length;
    
    // Проверяем наличие расширений (extensions)
    if pos + 2 > handshake_end {
        // Нет расширений
        return None;
    }
    
    // Получаем длину всех расширений
    let extensions_length = ((tls_data[pos] as usize) << 8) | (tls_data[pos + 1] as usize);
    pos += 2;
    
    if pos + extensions_length > handshake_end {
        return None;
    }
    
    let extensions_end = pos + extensions_length;
    
    // Ищем расширение SNI (Server Name Indication, тип 0)
    while pos + 4 <= extensions_end {
        let extension_type = ((tls_data[pos] as u16) << 8) | (tls_data[pos + 1] as u16);
        let extension_length = ((tls_data[pos + 2] as usize) << 8) | (tls_data[pos + 3] as usize);
        pos += 4;
        
        if pos + extension_length > extensions_end {
            return None;
        }
        
        // Нашли SNI (тип 0)
        if extension_type == 0 {
            // Должно быть достаточно данных для двухбайтного поля длины списка имен серверов
            if extension_length < 2 {
                pos += extension_length;
                continue;
            }
            
            let server_name_list_length = ((tls_data[pos] as usize) << 8) | (tls_data[pos + 1] as usize);
            if server_name_list_length + 2 > extension_length {
                pos += extension_length;
                continue;
            }
            
            let mut sni_pos = pos + 2;
            let sni_end = pos + 2 + server_name_list_length;
            
            // Парсим записи SNI
            while sni_pos + 3 <= sni_end {
                let name_type = tls_data[sni_pos];
                let name_length = ((tls_data[sni_pos + 1] as usize) << 8) | (tls_data[sni_pos + 2] as usize);
                sni_pos += 3;
                
                if sni_pos + name_length > sni_end {
                    break;
                }
                
                // Имя хоста (тип 0)
                if name_type == 0 {
                    // Пытаемся извлечь доменное имя как UTF-8 строку
                    match std::str::from_utf8(&tls_data[sni_pos..sni_pos + name_length]) {
                        Ok(domain) => {
                            // Дополнительно проверяем, что строка домена не пустая
                            let trimmed = domain.trim();
                            if !trimmed.is_empty() {
                                return Some(trimmed.to_string());
                            }
                        },
                        Err(_) => {
                            // При ошибке UTF-8 попробуем более лояльный метод декодирования
                            // Используем lossy-декодирование для замены некорректных UTF-8 последовательностей
                            let lossy_domain = String::from_utf8_lossy(&tls_data[sni_pos..sni_pos + name_length]).to_string();
                            let trimmed = lossy_domain.trim();
                            if !trimmed.is_empty() {
                                return Some(trimmed.to_string());
                            }
                        }
                    }
                }
                
                sni_pos += name_length;
            }
        }
        
        // Переходим к следующему расширению
        pos += extension_length;
    }

    None
}