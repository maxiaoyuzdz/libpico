using System;
using System.Text;
using System.Collections.Generic;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using LibPico;
using System.Threading;

namespace LibPicoTests
{
    [TestClass]
    public class TestSigmaVerifier
    {
        public struct EncKeys
        {
            public PicoBuffer pMacKey;
            public PicoBuffer pEncKey;
            public PicoBuffer vMacKey;
            public PicoBuffer vEncKey;
            public PicoBuffer sharedKey;
        }

        void send_start_message(Channel channel, int picoVersion, KeyPair picoEphemeralKey, Nonce picoNonce) {
            Json json = new Json();
            PicoBuffer buf = new PicoBuffer(0);
    
            json.add("picoVersion", (double)2);
            picoEphemeralKey.getpublicpem(buf);
            json.add("picoEphemeralPublicKey", buf);
            buf.clear();
            Base64.encode(picoNonce.get_buffer(), picoNonce.get_length(), buf);
            json.add("picoNonce", buf);
            buf.clear();
            json.serialize(buf);
            channel.write_buffer(buf);

            buf.delete();
            json.delete();
        }

        void receive_service_auth_message(Channel channel, ref EncKeys keys, KeyPair picoEphemeralKey, Nonce picoNonce, ref IntPtr serviceEphemKey, ref Nonce serviceNonce)
        {
            Json json = new Json();
            PicoBuffer buf = new PicoBuffer(0);
            PicoBuffer iv = new PicoBuffer(0);
            PicoBuffer cleartext = new PicoBuffer(0);

            channel.read(buf);
            json.deserialize(buf);

            Assert.AreEqual(json.get_decimal("sessionId"), 0);
            serviceEphemKey = CryptoSupport.read_base64_string_public_key(json.get_string("serviceEphemPublicKey"));
            buf.clear();
            Base64.decode(json.get_string("serviceNonce"), buf);
            serviceNonce = new Nonce();
            serviceNonce.set_buffer(buf);

            Base64.decode(json.get_string("iv"), iv);
            // Generate shared secrets	
            PicoBuffer sharedSecret;
            IntPtr vEphemPriv;
            SigmaKeyDeriv sigmakeyderiv;
            sharedSecret = new PicoBuffer(0);
            vEphemPriv = picoEphemeralKey.getprivatekey();
            KeyAgreement.generate_secret(vEphemPriv, serviceEphemKey, sharedSecret);
            sigmakeyderiv = new SigmaKeyDeriv();
            sigmakeyderiv.set(sharedSecret, picoNonce, serviceNonce);
            sharedSecret.delete();
            keys.pMacKey = new PicoBuffer(0);
            keys.pEncKey = new PicoBuffer(0);
            keys.vMacKey = new PicoBuffer(0);
            keys.vEncKey = new PicoBuffer(0);
            keys.sharedKey = new PicoBuffer(0);
            sigmakeyderiv.get_next_key(keys.pMacKey, 256);
            sigmakeyderiv.get_next_key(keys.pEncKey, 128);
            sigmakeyderiv.get_next_key(keys.vMacKey, 256);
            sigmakeyderiv.get_next_key(keys.vEncKey, 128);
            sigmakeyderiv.get_next_key(keys.sharedKey, 128);
            sigmakeyderiv.delete();

            buf.clear();
            Base64.decode(json.get_string("encryptedData"), buf);
            CryptoSupport.decrypt(keys.vEncKey, iv, buf, cleartext);

            int start = 0;
            int next = 0;
            PicoBuffer servicePublicKeyBytes = new PicoBuffer(0);
            PicoBuffer serviceSignature = new PicoBuffer(0);
            PicoBuffer serviceMac = new PicoBuffer(0);

            next = cleartext.copy_lengthprepend(start, servicePublicKeyBytes);
            IntPtr servicePublicKey = CryptoSupport.read_buffer_public_key(servicePublicKeyBytes);
            Assert.IsTrue(next > start);
            next = cleartext.copy_lengthprepend(start, serviceSignature);
            Assert.IsTrue(next > start);
            next = cleartext.copy_lengthprepend(start, serviceMac);
            Assert.IsTrue(next > start);
            // TODO assert signature

            json.delete();
            buf.delete();
            cleartext.delete();
            servicePublicKeyBytes.delete();
            serviceSignature.delete();
            serviceMac.delete();
        }

        void send_pico_auth_message(Channel channel, EncKeys keys, Nonce serviceNonce, KeyPair picoIdentityKey, KeyPair picoEphemeralKey, string extra_data_to_send)
        {
            Json json = new Json();
            PicoBuffer buf = new PicoBuffer(0);
            PicoBuffer toEncrypt = new PicoBuffer(0);
            
            picoIdentityKey.getpublicder(buf);
            toEncrypt.append_lengthprepend(buf);

            PicoBuffer toSign = new PicoBuffer(0);
            toSign.append(serviceNonce.get_buffer(), serviceNonce.get_length());
            toSign.append(new byte[]{0x00, 0x00, 0x00, 0x00});
            buf.clear();
            picoEphemeralKey.getpublicder(buf);
            toSign.append(buf);
            buf.clear();
            picoIdentityKey.sign_data(toSign, buf);
            toEncrypt.append_lengthprepend(buf);

            PicoBuffer mac = new PicoBuffer(0);
            buf.clear();
            picoIdentityKey.getpublicder(buf);
            CryptoSupport.generate_mac(keys.pMacKey, buf, mac);
            toEncrypt.append_lengthprepend(mac);

            PicoBuffer extraData = new PicoBuffer(0);
            extraData.append(extra_data_to_send);
            toEncrypt.append_lengthprepend(extraData);

            PicoBuffer iv = new PicoBuffer(16);
            CryptoSupport.generate_iv(iv);
            PicoBuffer encrypted = new PicoBuffer(0);
            CryptoSupport.encrypt(keys.pEncKey, iv, toEncrypt, encrypted);

            buf.clear();
            Base64.encode(encrypted, buf);
            json.add("encryptedData", buf);
            buf.clear();
            Base64.encode(iv, buf);
            json.add("iv", buf);
            json.add("sessionId", 0);

            buf.clear();
            json.serialize(buf);
            channel.write_buffer(buf);

            json.delete();
            buf.delete();
            toEncrypt.delete();
            toSign.delete();
            mac.delete();
            extraData.delete();
            iv.delete();
            encrypted.delete();
        }

        void receive_status_message(Channel channel, EncKeys keys, string expected_extra_data)
        {
            Json json = new Json();
            PicoBuffer buf = new PicoBuffer(0);
            PicoBuffer iv = new PicoBuffer(0);
            PicoBuffer cleartext = new PicoBuffer(0);

            channel.read(buf);
            json.deserialize(buf);
            Assert.AreEqual(json.get_decimal("sessionId"), 0);
            Base64.decode(json.get_string("iv"), iv);
            buf.clear();
            Base64.decode(json.get_string("encryptedData"), buf);
            CryptoSupport.decrypt(keys.vEncKey, iv, buf, cleartext);

            PicoBuffer receivedExtraData = new PicoBuffer(0);
            byte[] status = new byte[2];
            cleartext.copy_to_array(status, 2);
            Assert.AreEqual(status[0], 0x00);
            cleartext.copy_lengthprepend(1, receivedExtraData);
            
            receivedExtraData.append(new byte[]{0x00});
            Assert.AreEqual(receivedExtraData.to_string(), expected_extra_data);

            json.delete();
            buf.delete();
            cleartext.delete();
            iv.delete();
            receivedExtraData.delete();
        }


        void prover_main(string channel_name)
        {
            Channel channel = Channel.connect(channel_name);
            Nonce picoNonce = new Nonce();
            KeyPair picoEphemeralKey = new KeyPair();
            picoEphemeralKey.generate();
            KeyPair picoIdentityKey = new KeyPair();
            picoIdentityKey.generate();
            picoNonce.generate_random();

            Nonce serviceNonce = new Nonce();
            IntPtr serviceEphemKey = IntPtr.Zero;
            EncKeys keys = new EncKeys();

            // Send start message
            send_start_message(channel, 2, picoEphemeralKey, picoNonce);

            // Receive service auth message
            receive_service_auth_message(channel, ref keys, picoEphemeralKey, picoNonce, ref serviceEphemKey, ref serviceNonce);

            // Send pico auth message
            send_pico_auth_message(channel, keys, serviceNonce, picoIdentityKey, picoEphemeralKey, "Test data");

            // Receive status message
            receive_status_message(channel, keys, "123456");

            picoEphemeralKey.delete();
            picoIdentityKey.delete();
            channel.delete();
            picoNonce.delete();
            serviceNonce.delete();
        }
        
        [TestMethod]
        public void Verify()
        {
	        Channel channel;
	        Shared shared;
	        PicoBuffer returnedExtraData;

	        shared = new Shared();
	        shared.load_or_generate_keys("testkey.pub", "testkey.priv");
	        channel = new Channel();


            Thread prover_td = new Thread(() => prover_main(channel.get_name()));
            prover_td.Start();
	        
	        returnedExtraData = new PicoBuffer(0);

            Sigma.verify(shared, channel, null, "123456", returnedExtraData, null);
            returnedExtraData.append(new byte[] { 0x00 });
            Assert.AreEqual(returnedExtraData.to_string(), "Test data");

            prover_td.Join();

            shared.delete();
            channel.delete();
            returnedExtraData.delete();
        }

        [TestMethod]
        public void KeyDeriv()
        {
	        SigmaKeyDeriv sigmakeyderiv;
	        PicoBuffer sharedSecret;
	        Nonce picoNonce;
	        Nonce serviceNonce;
	        PicoBuffer keyBytes;
	        PicoBuffer nonceData;
	        PicoBuffer base64;

	        sharedSecret = new PicoBuffer(0);
	        sharedSecret.append("\x23\x02\x38\x40\x70\x23\x49\x08\x23\x04\x48\x20\x39\x48\x02\x70\x8");
	        nonceData = new PicoBuffer(0);
	        nonceData.append("\x01\x02\x03\x04\x05\x06\x07\x08");
	        picoNonce = new Nonce();
	        picoNonce.set_buffer(nonceData);

	        nonceData.clear();
	        nonceData.append("\x07\x04\x09\x02\x03\x07\x05\x06");
	        serviceNonce = new Nonce();
	        serviceNonce.set_buffer(nonceData);

	        nonceData.delete();

	        sigmakeyderiv = new SigmaKeyDeriv();
	        sigmakeyderiv.set(sharedSecret, picoNonce, serviceNonce);

            sharedSecret.delete(); ;
	        picoNonce.delete();
	        serviceNonce.delete();

	        // sharedKey
	        keyBytes = new PicoBuffer(0);
	        base64 = new PicoBuffer(0);
	        sigmakeyderiv.get_next_key(keyBytes, 128);
	        Base64.encode(keyBytes, base64);
	        base64.append(new byte[]{0x00});
            Assert.AreEqual(base64.to_string(), "7iU6mLgArgvtO9HW0lvk/g==");

	        // pMacKey
            keyBytes.clear();
            base64.clear();
            sigmakeyderiv.get_next_key(keyBytes, 256);
            Base64.encode(keyBytes, base64);
            base64.append(new byte[] { 0x00 });
            Assert.AreEqual(base64.to_string(), "L0VyA6JS5ZMggVMvJB22s61K+9INGk3OqK0eyJLMnSs=");
	        
	        // pEncKey
            keyBytes.clear();
            base64.clear();
            sigmakeyderiv.get_next_key(keyBytes, 128);
            Base64.encode(keyBytes, base64);
            base64.append(new byte[] { 0x00 });
            Assert.AreEqual(base64.to_string(), "ynUis+NzmrGp5yC3nX0Gjw==");

	        // vMacKey
            keyBytes.clear();
            base64.clear();
            sigmakeyderiv.get_next_key(keyBytes, 256);
            Base64.encode(keyBytes, base64);
            base64.append(new byte[] { 0x00 });
            Assert.AreEqual(base64.to_string(), "J1mluN+sD9qrhdQ83vd/o7BKQvsq5l80t7CuTcs6A0A=");

	        // pEncKey
            keyBytes.clear();
            base64.clear();
            sigmakeyderiv.get_next_key(keyBytes, 128);
            Base64.encode(keyBytes, base64);
            base64.append(new byte[] { 0x00 });
            Assert.AreEqual(base64.to_string(), "7HK9ZbFCzAiVXUnlzOGDVA==");

            keyBytes.delete();
            base64.delete();
            sigmakeyderiv.delete();
        }
    }
}


