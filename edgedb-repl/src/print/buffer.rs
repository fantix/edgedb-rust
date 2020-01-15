use std::fmt::Write;

use colorful::core::color_string::CString;
use colorful::core::StrMarker;

use crate::print::Printer;
use crate::print::stream::Stream;
use crate::print::formatter::ColorfulExt;


impl<T: Stream<Error=E>, E> Printer<T, E> {
    pub(in crate::print) fn flush_buf(&mut self) -> Result<(), E> {
        self.stream.write(&self.buffer)?;
        self.buffer.clear();
        Ok(())
    }
    pub(in crate::print) fn write(&mut self, s: CString)
        -> Result<(), E>
    {
        if self.colors {
            write!(&mut self.buffer, "{}", s)
                .expect("formatting CString always succeeds");
        } else {
            self.buffer.push_str(&s.to_str());
        }
        self.flush_buf()?;  // TODO: add a waterline
        Ok(())
    }
    pub(in crate::print) fn open_brace(&mut self) -> Result<(), E> {
        self.write("{".clear())
    }
    pub(in crate::print) fn comma(&mut self) -> Result<(), E> {
        self.comma = true;
        Ok(())
    }
    pub(in crate::print) fn close_brace(&mut self) -> Result<(), E> {
        self.write("}".clear())
    }
    pub(in crate::print) fn delimit(&mut self) -> Result<(), E> {
        if self.comma {
            self.write(", ".clear())?;
            self.comma = false;
        }
        Ok(())
    }
}
