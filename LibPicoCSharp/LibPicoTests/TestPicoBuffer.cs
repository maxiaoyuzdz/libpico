using System;
using System.Text;
using System.Collections.Generic;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using LibPico;
using System.Runtime.InteropServices;

namespace LibPicoTests
{
    [TestClass]
    public class TestPicoBuffer
    {
        [System.Runtime.InteropServices.DllImport("msvcrt.dll", CallingConvention = CallingConvention.Cdecl)]
        static extern int memcmp(byte[] b1, byte[] b2, UIntPtr count);

        [TestMethod]
        public void initial_state() {
            PicoBuffer b = new PicoBuffer(0);
            Assert.AreEqual(b.get_pos(), 0);
            Assert.AreEqual(b.get_size(), 2048);
            b.delete();
        }

        [TestMethod]
        public void append_string() {
	        PicoBuffer b;
	        b = new PicoBuffer(3);
	        b.append("1234567890");
            Assert.AreEqual(b.get_pos(), 10);
            Assert.AreEqual(b.get_size()%3, 0);
	        Assert.AreEqual(b.to_string(), "1234567890");
	        b.delete();
        }
        
        [TestMethod]
        public void append_buffer() {
	        PicoBuffer b;
	        PicoBuffer b2;
	        b = new PicoBuffer(3);
	        b2 = new PicoBuffer(3);
	        b.append("12345");
	        b2.append("67890");
            Assert.AreEqual(b.get_pos(), 5);
            Assert.AreEqual(b.get_size()%3, 0);
            Assert.AreEqual(b2.get_pos(), 5);
            Assert.AreEqual(b2.get_size()%3, 0);

            b2.append(b);

            Assert.AreEqual(b2.to_string(), "6789012345");
            b.delete();
            b2.delete();
        }

        [TestMethod]
        public void equals() {
	        PicoBuffer b = new PicoBuffer(3);
	        PicoBuffer b2 = new PicoBuffer(3);
	        b.append("1234");
	        b2.append("6789");

            Assert.IsFalse(b.equals(b2));
	
	        b2.clear();
	        b2.append("1234");
            Assert.IsTrue(b.equals(b2));

            b.set_pos(10);
	        Assert.IsFalse(b.equals(b2));

            b.delete();
            b2.delete();
        }

        [TestMethod]
        public void length_prepend() {
	        PicoBuffer b;
	        PicoBuffer b2;
	        b = new PicoBuffer(3);
	        b2 = new PicoBuffer(3);
	        b2.append("67890");
            Assert.AreEqual(b2.get_pos(), 5);
            Assert.AreEqual(b2.get_size()%3, 0);

            b.append_lengthprepend(b2);

            byte[] expected = new byte[] {0x00, 0x00, 0x00, 0x05,Convert.ToByte('6'),Convert.ToByte('7'),Convert.ToByte('8'),Convert.ToByte('9'),Convert.ToByte('0'), 0x00};
            byte[] ret = new byte[10];
            b.copy_to_array(ret, 10);
            CollectionAssert.AreEqual(ret, expected);

            b.delete();
            b2.delete();
        }

        [TestMethod]
        public void truncate() {
	        PicoBuffer b;
	        b = new PicoBuffer(3);
	        b.append("1234567890");
	        b.truncate(6);
            Assert.AreEqual(b.get_pos(), 4);
            Assert.AreEqual(b.get_size(), 6);
            Assert.AreEqual(b.to_string(), "1234");
            b.delete();
        }
    }
}

