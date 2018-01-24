using System;
using System.Text;
using System.Collections.Generic;
using System.Threading;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using LibPico;

namespace LibPicoTests
{
    [TestClass]
    public class TestChannel
    {
        
        void echo_main(string channel_name) {
	        Channel channel = Channel.connect(channel_name);
	        PicoBuffer buf = new PicoBuffer(0);
	        PicoBuffer toSend = new PicoBuffer(0);

	        channel.read(buf);
            toSend.append_lengthprepend(buf);
            byte[] bytesToSend = new byte[toSend.get_pos() + 1];
            toSend.copy_to_array(bytesToSend);
            channel.write(bytesToSend, bytesToSend.Length);
            
            buf.delete();
            toSend.delete();
            channel.delete();
        }


        [TestMethod]
        public void EchoTest()
        {
	        Channel channel = new Channel();
	        PicoBuffer buf = new PicoBuffer(0);
	        PicoBuffer recvbuf = new PicoBuffer(0);


            Thread echo_td = new Thread(() => echo_main(channel.get_name()));
            echo_td.Start();
	        
	        buf.append("HELLO WORLD!");
	        channel.write_buffer(buf);
	        channel.read(recvbuf);

	        recvbuf.append(new byte[]{0x00});
            Assert.AreEqual(recvbuf.to_string(), "HELLO WORLD!");

	        echo_td.Join();

	        channel.delete();
	        buf.delete();
	        recvbuf.delete();
        }


        [TestMethod]
        public void GetUrl() {
	        Channel channel = Channel.connect("c348ff95f0bd49aabe55ea35a637c680");
	        PicoBuffer buf = new PicoBuffer(0);

            channel.get_url(buf);
            buf.append(new byte[] { 0x00 });
            Assert.AreEqual(buf.to_string(), "http://rendezvous.mypico.org/channel/c348ff95f0bd49aabe55ea35a637c680");

            channel.delete();
            buf.delete();
        }
    }
}
