using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using LibPico;

namespace LibPicoTests
{
    [TestClass]
    public class TestUsers
    {
        [TestMethod]
        public void AddUsers()
        {
            KeyPair keypair1 = new KeyPair();
	        KeyPair keypair2 = new KeyPair();
	        keypair1.generate();
	        keypair2.generate();
	        PicoBuffer expected = new PicoBuffer(0);
            PicoBuffer symmetricKey1 = new PicoBuffer(0);
 	        PicoBuffer symmetricKey2 = new PicoBuffer(0);
 	        PicoBuffer symmetricKey;

            CryptoSupport.generate_symmetric_key(symmetricKey1, CryptoSupport.AESKEY_SIZE);
            CryptoSupport.generate_symmetric_key(symmetricKey2, CryptoSupport.AESKEY_SIZE);
            Assert.IsFalse(symmetricKey1.equals(symmetricKey2));

	        IntPtr pub1 = keypair1.getpublickey();
	        IntPtr pub2 = keypair2.getpublickey();

	        Users users = new Users();

            Assert.AreEqual(users.search_by_key(pub1).getIntPtr(), IntPtr.Zero);
            Assert.AreEqual(users.search_by_key(pub2).getIntPtr(), IntPtr.Zero);

	        users.add_user("one", pub1, symmetricKey1);

            Assert.AreEqual(users.search_by_key(pub2).getIntPtr(), IntPtr.Zero);
	        PicoBuffer user = users.search_by_key(pub1);
	        expected.clear();
            expected.append("one");
            Assert.IsTrue(user.equals(expected));
	    
	        users.add_user("two", pub2, symmetricKey2);
	    
	        user = users.search_by_key(pub1);
            expected.clear();
	        expected.append("one");
            Assert.IsTrue(user.equals(expected));
	        user = users.search_by_key(pub2);
	        expected.clear();
	        expected.append("two");
            Assert.IsTrue(user.equals(expected));

            // Check the correct symmetric keys are returned
            symmetricKey = users.search_symmetrickey_by_key(pub1);
            Assert.IsTrue(symmetricKey.equals(symmetricKey1));
            symmetricKey = users.search_symmetrickey_by_key(pub2);
            Assert.IsTrue(symmetricKey.equals(symmetricKey2));

            users.delete_all();
	        Assert.AreEqual(users.search_by_key(pub2).getIntPtr(), IntPtr.Zero);
            Assert.AreEqual(users.search_by_key(pub2).getIntPtr(), IntPtr.Zero);

            users.delete();
            expected.delete();
            keypair1.delete();
            keypair2.delete();
            symmetricKey1.delete();
            symmetricKey2.delete();
        }
        
        [TestMethod]
        public void export_users()
        {
            KeyPair keypair1 = new KeyPair();
	        KeyPair keypair2 = new KeyPair();
	        keypair1.generate();
	        keypair2.generate();
	        PicoBuffer expected = new PicoBuffer(0);
            PicoBuffer symmetricKey1 = new PicoBuffer(0);
 	        PicoBuffer symmetricKey2 = new PicoBuffer(0);
 	        PicoBuffer symmetricKey;

            CryptoSupport.generate_symmetric_key(symmetricKey1, CryptoSupport.AESKEY_SIZE);
            CryptoSupport.generate_symmetric_key(symmetricKey2, CryptoSupport.AESKEY_SIZE);
            Assert.IsFalse(symmetricKey1.equals(symmetricKey2));

            IntPtr pub1 = keypair1.getpublickey();
	        IntPtr pub2 = keypair2.getpublickey();

	        string filename = System.IO.Path.GetTempFileName();

            Users users = new Users();

            Assert.AreEqual(users.search_by_key(pub1).getIntPtr(), IntPtr.Zero);
            Assert.AreEqual(users.search_by_key(pub2).getIntPtr(), IntPtr.Zero);

	        users.add_user("one", pub1, symmetricKey1);
            users.add_user("two", pub2, symmetricKey2);

            PicoBuffer user = users.search_by_key(pub1);
	        expected.clear();
            expected.append("one");
            Assert.IsTrue(user.equals(expected));
	        
            user = users.search_by_key(pub2);
	        expected.clear();
            expected.append("two");
            Assert.IsTrue(user.equals(expected));

	        users.export(filename);

	        users.delete_all();
            Assert.AreEqual(users.search_by_key(pub1).getIntPtr(), IntPtr.Zero);
            Assert.AreEqual(users.search_by_key(pub2).getIntPtr(), IntPtr.Zero);

	        users.load(filename);
	
            user = users.search_by_key(pub1);
	        expected.clear();
            expected.append("one");
            Assert.IsTrue(user.equals(expected));	        
            user = users.search_by_key(pub2);
	        expected.clear();
            expected.append("two");
            Assert.IsTrue(user.equals(expected));

            // Check the correct symmetric keys are returned
            symmetricKey = users.search_symmetrickey_by_key(pub1);
            Assert.IsTrue(symmetricKey.equals(symmetricKey1));
            symmetricKey = users.search_symmetrickey_by_key(pub2);
            Assert.IsTrue(symmetricKey.equals(symmetricKey2));

            users.delete();
            expected.delete();
            keypair1.delete();
            keypair2.delete();
        }

        
        [TestMethod]
        public void filter_users()
        {
            KeyPair keypair1 = new KeyPair();
	        KeyPair keypair2 = new KeyPair();
	        keypair1.generate();
	        keypair2.generate();
	        PicoBuffer expected = new PicoBuffer(0);
            PicoBuffer symmetricKey1 = new PicoBuffer(0);
            PicoBuffer symmetricKey2 = new PicoBuffer(0);
            PicoBuffer symmetricKey;

            CryptoSupport.generate_symmetric_key(symmetricKey1, CryptoSupport.AESKEY_SIZE);
            CryptoSupport.generate_symmetric_key(symmetricKey2, CryptoSupport.AESKEY_SIZE);
            Assert.IsFalse(symmetricKey1.equals(symmetricKey2));


            IntPtr pub1 = keypair1.getpublickey();
	        IntPtr pub2 = keypair2.getpublickey();

	        Users users = new Users();

            Assert.AreEqual(users.search_by_key(pub1).getIntPtr(), IntPtr.Zero);
            Assert.AreEqual(users.search_by_key(pub2).getIntPtr(), IntPtr.Zero);
                        
	        users.add_user("one", pub1, symmetricKey1);
            users.add_user("two", pub2, symmetricKey2);

            PicoBuffer user = users.search_by_key(pub1);
	        expected.clear();
            expected.append("one");
            Assert.IsTrue(user.equals(expected));
	        
            user = users.search_by_key(pub2);
	        expected.clear();
            expected.append("two");
            Assert.IsTrue(user.equals(expected));

	        Users filtered = new Users();

	        users.filter_by_name("one", filtered);
            Assert.AreEqual(filtered.search_by_key(pub2).getIntPtr(), IntPtr.Zero);
            user = users.search_by_key(pub1);
	        expected.clear();
            expected.append("one");
            Assert.IsTrue(user.equals(expected));

            // Check the correct symmetric keys are returned
            symmetricKey = users.search_symmetrickey_by_key(pub1);
            Assert.IsTrue(symmetricKey.equals(symmetricKey1));
            symmetricKey = users.search_symmetrickey_by_key(pub2);
            Assert.IsTrue(symmetricKey.equals(symmetricKey2));

            users.delete();
            expected.delete();
            filtered.delete();
            keypair1.delete();
            keypair2.delete();
        }


        [TestMethod]
        public void move_users()
        {
            KeyPair keypair1 = new KeyPair();
	        KeyPair keypair2 = new KeyPair();
	        keypair1.generate();
	        keypair2.generate();
	        PicoBuffer expected = new PicoBuffer(0);
            IntPtr pub1 = keypair1.getpublickey();
	        IntPtr pub2 = keypair2.getpublickey();
	        Users users = new Users();
            PicoBuffer symmetricKey1 = new PicoBuffer(0);
            PicoBuffer symmetricKey2 = new PicoBuffer(0);
            PicoBuffer symmetricKey;

            CryptoSupport.generate_symmetric_key(symmetricKey1, CryptoSupport.AESKEY_SIZE);
            CryptoSupport.generate_symmetric_key(symmetricKey2, CryptoSupport.AESKEY_SIZE);
            Assert.IsFalse(symmetricKey1.equals(symmetricKey2));
	        users.add_user("one", pub1, symmetricKey1);
            users.add_user("two", pub2, symmetricKey2);

            PicoBuffer user = users.search_by_key(pub1);
            expected.clear();
            expected.append("one");
            Assert.IsTrue(user.equals(expected));
            user = users.search_by_key(pub2);
            expected.clear();
            expected.append("two");
            Assert.IsTrue(user.equals(expected));

	        Users moved = new Users();

	        users.move_list(moved);
            Assert.AreEqual(users.search_by_key(pub1).getIntPtr(), IntPtr.Zero);
            Assert.AreEqual(users.search_by_key(pub2).getIntPtr(), IntPtr.Zero);

            user = moved.search_by_key(pub1);
            expected.clear();
            expected.append("one");
            Assert.IsTrue(user.equals(expected));
            user = moved.search_by_key(pub2);
            expected.clear();
            expected.append("two");
            Assert.IsTrue(user.equals(expected));

            // Check the correct symmetric keys are returned
            symmetricKey = moved.search_symmetrickey_by_key(pub1);
            Assert.IsTrue(symmetricKey.equals(symmetricKey1));
            symmetricKey = moved.search_symmetrickey_by_key(pub2);
            Assert.IsTrue(symmetricKey.equals(symmetricKey2));

	        users.delete();
            expected.delete();
            moved.delete();
            keypair1.delete();
            keypair2.delete();
        }
    }
}
