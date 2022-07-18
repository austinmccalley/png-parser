use core::panic;
use std::{
    env,
    fs::File,
    io::{BufReader, Read, Write},
    process::exit,
};

use inflate::inflate_bytes_zlib;

// PNG Spec: https://www.w3.org/TR/PNG/
// Guide: https://medium.com/achiev/understanding-and-decoding-png-format-example-in-ts-b31fdde1151b

const PNG_HEADER: [u8; 8] = [137, 80, 78, 71, 13, 10, 26, 10];
const IHDR_HEADER: [u8; 4] = [73, 72, 68, 82];
const IDAT_HEADER: [u8; 4] = [73, 68, 65, 84];
const IEND_HEADER: [u8; 4] = [73, 69, 78, 68];
const T_RNS_HEADER: [u8; 4] = [116, 82, 78, 83];
const C_HRM_HEADER: [u8; 4] = [99, 72, 82, 77];
const G_AMA_HEADER: [u8; 4] = [103, 65, 77, 65];
const I_CCP_HEADER: [u8; 4] = [105, 67, 67, 80];
const SBIT_HEADER: [u8; 4] = [115, 66, 73, 84];
const S_RGB_HEADER: [u8; 4] = [115, 82, 71, 66];
const T_EXT_HEADER: [u8; 4] = [116, 69, 88, 116];
const Z_TXT_HEADER: [u8; 4] = [112, 84, 88, 116];
const I_TXT_HEADER: [u8; 4] = [105, 84, 88, 116];
const B_KGD_HEADER: [u8; 4] = [98, 75, 71, 68];
const H_IST_HEADER: [u8; 4] = [104, 73, 83, 84];
const P_HYS_HEADER: [u8; 4] = [112, 72, 89, 115];
const S_PLT_HEADER: [u8; 4] = [115, 80, 76, 84];
const T_IME_HEADER: [u8; 4] = [116, 73, 77, 69];

struct PngImage {
    content: Vec<[u8; 4]>,
    width: i64,
    height: i64,
    bit_depth: i16,
    color_type: i16,
    compression_method: i16,
    filter_method: i16,
    interlace_method: i16,
    idat_data: Vec<u8>,
}

struct PngChunk {
    total_length: usize,
    data_length: usize,
    data_type: [u8; 4],
    data: Vec<u8>,
    crc: Vec<u8>,
}

fn as_be(array: &[u8]) -> usize {
    let len = array.len();
    let mut mult = (len - 1) * 8;
    let mut num = 0;

    for i in 0..len {
        num += (array[i] as usize) << mult;
        if mult != 0 {
            mult -= 8;
        }
    }
    num
}

fn as_u32_be(array: &[u8; 4]) -> u32 {
    ((array[0] as u32) << 24)
        + ((array[1] as u32) << 16)
        + ((array[2] as u32) << 8)
        + ((array[3] as u32) << 0)
}

fn get_length(buffer: &Vec<u8>) -> usize {
    assert!(
        buffer.len() >= 4,
        "Buffer length must be greater than to or equal to 4. We got a buffer of length {}",
        buffer.len()
    );

    // Buffer from length bytes
    let len_bytes = &buffer[0..4];
    let bytes = type_array_vec(len_bytes);

    // We want to return the UIntBE of the buffer
    let num = as_be(&bytes);
    return num as usize;
}

fn type_array_vec(barry: &[u8]) -> [u8; 4] {
    assert!(
        barry.len() == 4,
        "Array passed does not have a length of 4, found {}",
        barry.len()
    );
    barry.try_into().expect("slice with incorrect length")
}

fn get_type(buffer: &Vec<u8>) -> [u8; 4] {
    let type_byte = &buffer[4..8];
    let buf = type_array_vec(type_byte);

    return buf;
}

fn get_data(buffer: &Vec<u8>, len: &usize) -> Vec<u8> {
    return (&buffer[8..(8 + *len)]).to_vec();
}

fn get_crc(buffer: &Vec<u8>, len: &usize) -> Vec<u8> {
    return (&buffer[8 + *len..8 + *len + 4]).to_vec();
}

fn build_chunk(buffer: Vec<u8>) -> PngChunk {
    let len = get_length(&buffer);

    return PngChunk {
        data_length: len,
        data_type: get_type(&buffer),
        data: get_data(&buffer, &len),
        crc: get_crc(&buffer, &len),
        total_length: len + 12,
    };
}

fn parse_ihdr_chunk(chunk: &PngChunk, png: &mut PngImage) {
    let data = &chunk.data;
    assert!(
        data.len() >= 13,
        "IHDR data must be gte to 13, we got {}",
        data.len()
    );

    png.width = as_u32_be(&type_array_vec(&data[0..4])) as i64;
    png.height = as_u32_be(&type_array_vec(&data[4..8])) as i64;

    png.bit_depth = *&data[8..9][0] as i16;
    assert_eq!(png.bit_depth, 8, "Bit depth not supported");

    png.compression_method = *&data[10..11][0] as i16;
    assert_eq!(
        png.compression_method, 0,
        "Compression method not supported"
    );

    png.filter_method = *&data[11..12][0] as i16;
    assert_eq!(png.filter_method, 0, "Filter method not supported");

    png.interlace_method = *&data[12..13][0] as i16;
    assert_eq!(png.interlace_method, 0, "Interlace method not supported");
}

fn add_idat_chunk(chunk: &PngChunk, png: &mut PngImage) {
    let mut new_vec = chunk.data.to_vec();
    png.idat_data.append(&mut new_vec);
}

fn u8_to_u16(array: &[u8; 4]) -> [u16; 4] {
    let mut arr: [u16; 4] = [0, 0, 0, 0];

    arr[0] = array[0] as u16;
    arr[1] = array[1] as u16;
    arr[2] = array[2] as u16;
    arr[3] = array[3] as u16;

    arr
}

fn parse_sub_filter(pixels_data: Vec<[u8; 4]>) -> Vec<[u8; 4]> {
    let mut content: Vec<[u8; 4]> = Vec::new();
    let mut previous: [u16; 4] = [0, 0, 0, 0];

    for pixel in pixels_data {
        let mut e0 = pixel[0] as u16 + previous[0];
        let mut e1 = pixel[1] as u16 + previous[1];
        let mut e2 = pixel[2] as u16 + previous[2];
        let mut e3 = pixel[3] as u16 + previous[3];

        e0 = e0 % 256;
        e1 = e1 % 256;
        e2 = e2 % 256;
        e3 = e3 % 256;

        let new_array = [e0 as u8, e1 as u8, e2 as u8, e3 as u8];
        previous = u8_to_u16(&new_array);
        content.push(new_array);
    }

    content
}

fn parse_up_filter(metadata: &[u64; 2], png: &mut PngImage) -> Vec<[u8; 4]> {
    let mut content: Vec<[u8; 4]> = Vec::new();

    let width = png.width as u64;

    let plp_start: usize = ((metadata[0] / metadata[1] - 1) * width)
        .try_into()
        .unwrap();
    let plp_end: usize = ((metadata[0] / metadata[1] - 1) * width + width)
        .try_into()
        .unwrap();

    assert!(
        plp_end >= plp_start,
        "Previous line pixels end must be greater than its start. Got {} as start and {} as end",
        plp_start,
        plp_end
    );

    let previous_line_pixels = &png.content;

    for (i, pixel) in previous_line_pixels.iter().enumerate() {
        let previous = u8_to_u16(&previous_line_pixels[i]);

        let mut e0 = pixel[0] as u16 + previous[0];
        let mut e1 = pixel[1] as u16 + previous[1];
        let mut e2 = pixel[2] as u16 + previous[2];
        let mut e3 = pixel[3] as u16 + previous[3];

        e0 %= 256;
        e1 %= 256;
        e2 %= 256;
        e3 %= 256;

        let new_array = [e0 as u8, e1 as u8, e2 as u8, e3 as u8];
        content.push(new_array);
    }

    content
}

fn parse_idat_data(png: &mut PngImage) {
    let encoded = png.idat_data.to_vec();

    let data_wrapped = inflate_bytes_zlib(&encoded);

    let data = data_wrapped.unwrap();

    let mut pos = 0;

    println!("IMG H: {}, W: {}", png.height, png.width);

    let scan_line_length = (png.width * 4 + 1) as usize; // 4 bytes per pixel + 1 for filter

    while pos < data.len() {
        if data.len() < pos || data.len() < pos + scan_line_length {
            println!("Failed to iterate due to out of bounce errors.")
        } else {
            assert!(
                data.len() >= pos,
                "Start of data position is greater than end of data. {} !>= {}",
                data.len(),
                pos
            );

            assert!(
                data.len() >= pos + scan_line_length,
                "End of data position is greater than end of data. {} !>= {}",
                data.len(),
                pos + scan_line_length
            );

            let line = data[pos..pos + scan_line_length].to_vec();
            let filter = line[0];
            let mut pixels_data_vec: Vec<Vec<u8>> = Vec::new();

            let mut line_pos = 1;
            while line_pos < line.len() {
                assert!(
                    line.len() > line_pos,
                    "Start of line position is greater than end of line. {} !>= {}",
                    line.len(),
                    line_pos
                );
                assert!(
                    line.len() >= line_pos + 4,
                    "End of line position is greater than end of line. {} !>= {}",
                    line.len(),
                    line_pos + 4
                );

                pixels_data_vec.push(line[line_pos..line_pos + 4].to_vec());
                line_pos += 4;
            }

            // Parse pixelsData from Vec<Vec<u8>> to Vec<[u8; 4]>
            let pixels_data = pixels_data_vec
                .iter()
                .map(|f| type_array_vec(f))
                .collect::<Vec<[u8; 4]>>();

            // Process line data
            match filter {
                0 => {
                    // No filter
                    let len = pixels_data_vec.len();
                    for i in 0..len {
                        let v = &pixels_data_vec[i];
                        let ba = type_array_vec(&v);
                        png.content.push(ba);
                    }
                }
                1 => {
                    // Sub filter
                    let content = png.content.to_vec();
                    let res = parse_sub_filter(pixels_data);
                    png.content = [content, res].concat()
                }
                2 => {
                    // Up filter
                    let content = png.content.to_vec();
                    let res = parse_up_filter(&[pos as u64, scan_line_length as u64], png);

                    png.content = [content, res].concat();
                }
                _ => {
                    let len = pixels_data_vec.len();
                    for _ in 0..len {
                        png.content.push([0, 0, 0, 255]);
                    }
                }
            }
        }

        pos += scan_line_length;
    }
    println!("Done processing IDAT data");
}

fn parse_png(f: File, png: &mut PngImage) -> &mut PngImage {
    let mut buffer_reader = BufReader::new(f);
    let mut contents = Vec::new();
    let buf_result = buffer_reader.read_to_end(&mut contents);

    assert!(buf_result.is_ok() && !buf_result.is_err());

    let buffer_size = contents.len();

    let png_num = &contents[0..8];
    let is_png = check_png(png_num.to_vec());
    assert!(
        is_png.is_ok() && !is_png.is_err(),
        "{}",
        is_png.unwrap_err()
    );

    let mut i: usize = 8;

    while i < buffer_size {
        let chunk = build_chunk((&contents[i..]).to_vec());

        match chunk.data_type {
            IHDR_HEADER => {
                println!("IHDR HEADER");
                parse_ihdr_chunk(&chunk, png)
            }
            IDAT_HEADER => {
                println!("IDAT HEADER");
                add_idat_chunk(&chunk, png)
            }
            IEND_HEADER => {
                println!("IEND HEADER");
                parse_idat_data(png);
            }
            T_RNS_HEADER => {
                println!("tRNS HEADER")
            }
            C_HRM_HEADER => {
                println!("cHRM HEADER");
            }
            G_AMA_HEADER => {
                println!("gama header")
            }
            I_CCP_HEADER => {
                println!("iccp header")
            }
            SBIT_HEADER => {
                println!("sbit header")
            }
            S_RGB_HEADER => {
                println!("srgb header")
            }
            T_EXT_HEADER => {
                println!("text header")
            }
            Z_TXT_HEADER => {
                println!("ztxt header")
            }
            I_TXT_HEADER => {
                println!("itxt header")
            }
            B_KGD_HEADER => {
                println!("bkgd header")
            }
            H_IST_HEADER => {
                println!("hist header")
            }
            P_HYS_HEADER => {
                println!("phys header")
            }
            S_PLT_HEADER => {
                println!("splt header")
            }
            T_IME_HEADER => {
                println!("time header")
            }

            _ => {
                println!("Unknown header {:X?}", chunk.data_type);
            }
        }

        i += chunk.total_length;
    }

    png
}

fn check_png(buffer: Vec<u8>) -> Result<Vec<u8>, &'static str> {
    assert!(
        buffer.len() == PNG_HEADER.len(),
        "PNG header is incorrect length. Length should be {} found {}",
        PNG_HEADER.len(),
        buffer.len()
    );

    for i in 0..PNG_HEADER.len() {
        assert!(
            buffer[i] == PNG_HEADER[i],
            "Value in header should be equal to PNG header. Found {} instead of {} at position {}",
            buffer[i],
            PNG_HEADER[i],
            i
        );
    }

    Ok(buffer)
}

pub fn main() {
    let args: Vec<String> = env::args().collect();
    let mut img_path: String = "imgs/lena.png".to_string();

    if args.len() > 1 {
        let string_arg = &args[1];
        img_path = string_arg.to_string();
    }

    // We are going to first import our image and get its dimensions
    let file_wrapped = File::open(img_path);
    // let file = file_wrapped.unwrap();

    if file_wrapped.is_err() && !file_wrapped.is_ok() {
        let file_error = file_wrapped.unwrap_err();
        println!("{}", file_error.to_string());
        exit(1);
    }

    assert!(file_wrapped.is_ok() && !file_wrapped.is_err());
    let file = file_wrapped.unwrap();
    let png = &mut PngImage {
        content: Vec::new(),
        idat_data: Vec::new(),
        width: -1,
        height: -1,
        bit_depth: -1,
        color_type: -1,
        compression_method: -1,
        filter_method: -1,
        interlace_method: -1,
    };

    let parsed = parse_png(file, png);

    let dir = env::current_dir();
    let current_dir = match dir {
        Err(error) => {
            panic!("There was a problem getting the current dir: {:?}", error);
        }
        Ok(s) => s,
    };

    let temp_file = current_dir.join("file.txt");
    let mut w_file = File::create(&temp_file).unwrap();

    let contents = &parsed.content;

    for i in 0..contents.len() {
        let v = contents[i];
        let s = format!("[ {}, {}, {}, {}]", v[0], v[1], v[2], v[3]);
        let res = writeln!(&mut w_file, "{}", s);
        let _s = match res {
            Err(error) => {
                panic!("There was a problem writing to the file: {:?}", error);
            }
            Ok(s) => s,
        };
    }

    println!("Done! Wrote to {:?}", temp_file.as_path().to_str());
}
