#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ThemeMode {
    Light,
    Dark,
}

impl ThemeMode {
    pub const fn label(self) -> &'static str {
        match self {
            Self::Light => "Light",
            Self::Dark => "Dark",
        }
    }

    pub const fn toggled(self) -> Self {
        match self {
            Self::Light => Self::Dark,
            Self::Dark => Self::Light,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Palette {
    pub window: u32,
    pub sidebar: u32,
    pub surface: u32,
    pub text: u32,
    pub muted_text: u32,
    pub accent: u32,
    pub success: u32,
    pub warning: u32,
    pub danger: u32,
}

pub const fn palette(mode: ThemeMode) -> Palette {
    match mode {
        ThemeMode::Light => Palette {
            window: rgb(245, 247, 250),
            sidebar: rgb(27, 46, 72),
            surface: rgb(255, 255, 255),
            text: rgb(30, 41, 59),
            muted_text: rgb(71, 85, 105),
            accent: rgb(0, 105, 190),
            success: rgb(22, 130, 82),
            warning: rgb(180, 112, 0),
            danger: rgb(190, 48, 48),
        },
        ThemeMode::Dark => Palette {
            window: rgb(22, 27, 34),
            sidebar: rgb(14, 22, 34),
            surface: rgb(34, 42, 53),
            text: rgb(232, 238, 247),
            muted_text: rgb(180, 194, 214),
            accent: rgb(68, 159, 235),
            success: rgb(72, 190, 124),
            warning: rgb(238, 173, 64),
            danger: rgb(244, 112, 112),
        },
    }
}

const fn rgb(red: u8, green: u8, blue: u8) -> u32 {
    red as u32 | ((green as u32) << 8) | ((blue as u32) << 16)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn theme_toggle_retains_two_contrasting_modes() {
        assert_eq!(ThemeMode::Light.toggled(), ThemeMode::Dark);
        assert_ne!(
            palette(ThemeMode::Light).window,
            palette(ThemeMode::Dark).window
        );
    }
}
