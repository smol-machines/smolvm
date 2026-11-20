//! SSH terminal modes use portable RFC 4254 numbers, never host termios bits.
use std::io;

#[cfg(target_os = "linux")]
pub fn apply(fd: i32, modes: &[(u8, u32)]) -> io::Result<()> {
    use libc::*;
    if modes.len() > 128 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "too many terminal modes",
        ));
    }
    let mut state = std::mem::MaybeUninit::<termios>::uninit();
    // SAFETY: tcgetattr initializes state for this owned, open slave descriptor.
    if unsafe { tcgetattr(fd, state.as_mut_ptr()) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let mut state = unsafe { state.assume_init() };
    for &(opcode, value) in modes {
        if opcode == 0 || opcode >= 160 {
            break;
        }
        let cc = match opcode {
            1 => Some(VINTR),
            2 => Some(VQUIT),
            3 => Some(VERASE),
            4 => Some(VKILL),
            5 => Some(VEOF),
            6 => Some(VEOL),
            7 => Some(VEOL2),
            8 => Some(VSTART),
            9 => Some(VSTOP),
            10 => Some(VSUSP),
            12 => Some(VREPRINT),
            13 => Some(VWERASE),
            14 => Some(VLNEXT),
            16 => Some(VSWTC),
            18 => Some(VDISCARD),
            _ => None,
        };
        if let Some(index) = cc {
            let value = u8::try_from(value).map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "invalid terminal control character",
                )
            })?;
            state.c_cc[index] = if value == 255 { _POSIX_VDISABLE } else { value };
            continue;
        }
        let flag = match opcode {
            30 => Some((&mut state.c_iflag, IGNPAR)),
            31 => Some((&mut state.c_iflag, PARMRK)),
            32 => Some((&mut state.c_iflag, INPCK)),
            33 => Some((&mut state.c_iflag, ISTRIP)),
            34 => Some((&mut state.c_iflag, INLCR)),
            35 => Some((&mut state.c_iflag, IGNCR)),
            36 => Some((&mut state.c_iflag, ICRNL)),
            37 => Some((&mut state.c_iflag, IUCLC)),
            38 => Some((&mut state.c_iflag, IXON)),
            39 => Some((&mut state.c_iflag, IXANY)),
            40 => Some((&mut state.c_iflag, IXOFF)),
            41 => Some((&mut state.c_iflag, IMAXBEL)),
            42 => Some((&mut state.c_iflag, IUTF8)),
            50 => Some((&mut state.c_lflag, ISIG)),
            51 => Some((&mut state.c_lflag, ICANON)),
            52 => Some((&mut state.c_lflag, XCASE)),
            53 => Some((&mut state.c_lflag, ECHO)),
            54 => Some((&mut state.c_lflag, ECHOE)),
            55 => Some((&mut state.c_lflag, ECHOK)),
            56 => Some((&mut state.c_lflag, ECHONL)),
            57 => Some((&mut state.c_lflag, NOFLSH)),
            58 => Some((&mut state.c_lflag, TOSTOP)),
            59 => Some((&mut state.c_lflag, IEXTEN)),
            60 => Some((&mut state.c_lflag, ECHOCTL)),
            61 => Some((&mut state.c_lflag, ECHOKE)),
            62 => Some((&mut state.c_lflag, PENDIN)),
            70 => Some((&mut state.c_oflag, OPOST)),
            71 => Some((&mut state.c_oflag, OLCUC)),
            72 => Some((&mut state.c_oflag, ONLCR)),
            73 => Some((&mut state.c_oflag, OCRNL)),
            74 => Some((&mut state.c_oflag, ONOCR)),
            75 => Some((&mut state.c_oflag, ONLRET)),
            92 => Some((&mut state.c_cflag, PARENB)),
            93 => Some((&mut state.c_cflag, PARODD)),
            _ => None,
        };
        if let Some((flags, mask)) = flag {
            if value == 0 {
                *flags &= !mask;
            } else {
                *flags |= mask;
            }
        } else if value != 0 && (opcode == 90 || opcode == 91) {
            state.c_cflag = (state.c_cflag & !CSIZE) | if opcode == 90 { CS7 } else { CS8 };
        } else if opcode == 128 || opcode == 129 {
            // Rates not representable by this platform leave its default intact.
            let speed = match value {
                0 => Some(B0),
                50 => Some(B50),
                75 => Some(B75),
                110 => Some(B110),
                134 => Some(B134),
                150 => Some(B150),
                200 => Some(B200),
                300 => Some(B300),
                600 => Some(B600),
                1200 => Some(B1200),
                1800 => Some(B1800),
                2400 => Some(B2400),
                4800 => Some(B4800),
                9600 => Some(B9600),
                19200 => Some(B19200),
                38400 => Some(B38400),
                57600 => Some(B57600),
                115200 => Some(B115200),
                230400 => Some(B230400),
                460800 => Some(B460800),
                500000 => Some(B500000),
                576000 => Some(B576000),
                921600 => Some(B921600),
                1000000 => Some(B1000000),
                1152000 => Some(B1152000),
                1500000 => Some(B1500000),
                2000000 => Some(B2000000),
                2500000 => Some(B2500000),
                3000000 => Some(B3000000),
                3500000 => Some(B3500000),
                4000000 => Some(B4000000),
                _ => None,
            };
            if let Some(speed) = speed {
                // SAFETY: state is initialized; speed is a platform constant.
                let result = unsafe {
                    if opcode == 128 {
                        cfsetispeed(&mut state, speed)
                    } else {
                        cfsetospeed(&mut state, speed)
                    }
                };
                if result != 0 {
                    return Err(io::Error::last_os_error());
                }
            }
        }
    }
    // SAFETY: apply the initialized state before spawning the child.
    if unsafe { tcsetattr(fd, TCSANOW, &state) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
pub fn apply(_: i32, _: &[(u8, u32)]) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "controlled terminals require Linux",
    ))
}
