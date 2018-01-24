using System;
using System.Runtime.InteropServices;

namespace LibPico
{
    public static class PicoDLL
    {
        private const string dllLocation = @"pico.dll";

        [DllImport(dllLocation, CallingConvention = CallingConvention.Cdecl)]
        public static extern IntPtr users_new();
        [DllImport(dllLocation, CallingConvention = CallingConvention.Cdecl)]
        public static extern void users_delete(IntPtr users);
        [DllImport(dllLocation, CallingConvention = CallingConvention.Cdecl)]
        public static extern int users_add_user(IntPtr users, string name, IntPtr key, IntPtr symmetric_key);
        [DllImport(dllLocation, CallingConvention = CallingConvention.Cdecl)]
        public static extern int users_export(IntPtr users, string file);
        [DllImport(dllLocation, CallingConvention = CallingConvention.Cdecl)]
        public static extern int users_load(IntPtr users, string file);
        [DllImport(dllLocation, CallingConvention = CallingConvention.Cdecl)]
        public static extern IntPtr users_search_by_key(IntPtr users, IntPtr key);
        [DllImport(dllLocation, CallingConvention = CallingConvention.Cdecl)]
        public static extern void users_delete_all(IntPtr users);
        [DllImport(dllLocation, CallingConvention = CallingConvention.Cdecl)]
        public static extern void users_print(IntPtr users);
        [DllImport(dllLocation, CallingConvention = CallingConvention.Cdecl)]
        public static extern void users_move_list(IntPtr users, IntPtr to);
        [DllImport(dllLocation, CallingConvention = CallingConvention.Cdecl)]
        public static extern int users_filter_by_name(IntPtr users, string name, IntPtr result);
        [DllImport(dllLocation, CallingConvention = CallingConvention.Cdecl)]
        public static extern IntPtr users_search_symmetrickey_by_key(IntPtr users, IntPtr picoIdentityPublicKey);

        [DllImport(dllLocation, CallingConvention = CallingConvention.Cdecl)]
        public static extern IntPtr nonce_new();
        [DllImport(dllLocation, CallingConvention = CallingConvention.Cdecl)]
        public static extern void nonce_delete(IntPtr nonce);
        [DllImport(dllLocation, CallingConvention = CallingConvention.Cdecl)]
        public static extern void nonce_set_buffer(IntPtr nonce, IntPtr value);
        [DllImport(dllLocation, CallingConvention = CallingConvention.Cdecl)]
        public static extern void nonce_generate_random(IntPtr nonce);
        [DllImport(dllLocation, CallingConvention = CallingConvention.Cdecl)]
        public static extern IntPtr nonce_get_buffer(IntPtr nonce);
        [DllImport(dllLocation, CallingConvention = CallingConvention.Cdecl)]
        public static extern int nonce_get_length(IntPtr nonce);

        [DllImport(dllLocation, CallingConvention = CallingConvention.Cdecl)]
        public static extern IntPtr shared_new();
        [DllImport(dllLocation, CallingConvention = CallingConvention.Cdecl)]
        public static extern void shared_delete(IntPtr shared);
        [DllImport(dllLocation, CallingConvention = CallingConvention.Cdecl)]
        public static extern void shared_generate_shared_secrets(IntPtr shared);
        [DllImport(dllLocation, CallingConvention = CallingConvention.Cdecl)]
        public static extern void shared_load_or_generate_keys(IntPtr shared, string key_public, string key_private);
        [DllImport(dllLocation, CallingConvention = CallingConvention.Cdecl)]
        public static extern IntPtr shared_get_service_nonce(IntPtr shared);
        [DllImport(dllLocation, CallingConvention = CallingConvention.Cdecl)]
        public static extern IntPtr shared_get_pico_nonce(IntPtr shared);
        [DllImport(dllLocation, CallingConvention = CallingConvention.Cdecl)]
        public static extern IntPtr shared_get_service_identity_key(IntPtr shared);
        [DllImport(dllLocation, CallingConvention = CallingConvention.Cdecl)]
        public static extern IntPtr shared_get_service_ephemeral_key(IntPtr shared);
        [DllImport(dllLocation, CallingConvention = CallingConvention.Cdecl)]
        public static extern void shared_set_pico_identity_public_key(IntPtr shared, IntPtr picoIdentityPublicKey);
        [DllImport(dllLocation, CallingConvention = CallingConvention.Cdecl)]
        public static extern IntPtr shared_get_pico_identity_public_key(IntPtr shared);
        [DllImport(dllLocation, CallingConvention = CallingConvention.Cdecl)]
        public static extern void shared_set_pico_ephemeral_public_key(IntPtr shared, IntPtr picoEphemeralPublicKey);
        [DllImport(dllLocation, CallingConvention = CallingConvention.Cdecl)]
        public static extern IntPtr shared_get_pico_ephemeral_public_key(IntPtr shared);
        [DllImport(dllLocation, CallingConvention = CallingConvention.Cdecl)]
        public static extern IntPtr shared_get_prover_enc_key(IntPtr shared);
        [DllImport(dllLocation, CallingConvention = CallingConvention.Cdecl)]
        public static extern IntPtr shared_get_verifier_enc_key(IntPtr shared);
        [DllImport(dllLocation, CallingConvention = CallingConvention.Cdecl)]
        public static extern IntPtr shared_get_prover_mac_key(IntPtr shared);
        [DllImport(dllLocation, CallingConvention = CallingConvention.Cdecl)]
        public static extern IntPtr shared_get_verifier_mac_key(IntPtr shared);

        [DllImport(dllLocation, CallingConvention = CallingConvention.Cdecl)]
        public static extern IntPtr keypair_new();
        [DllImport(dllLocation, CallingConvention = CallingConvention.Cdecl)]
        public static extern void keypair_delete(IntPtr keypair);
        [DllImport(dllLocation, CallingConvention = CallingConvention.Cdecl)]
        public static extern void keypair_generate(IntPtr keypair);
        [DllImport(dllLocation, CallingConvention = CallingConvention.Cdecl)]
        public static extern void keypair_export(IntPtr keypair, string key_public, string key_private);
        [DllImport(dllLocation, CallingConvention = CallingConvention.Cdecl)]
        public static extern bool keypair_import(IntPtr keypair, string key_public, string key_private);
        [DllImport(dllLocation, CallingConvention = CallingConvention.Cdecl)]
        public static extern void keypair_clear_keys(IntPtr keypair);
        [DllImport(dllLocation, CallingConvention = CallingConvention.Cdecl)]
        public static extern void keypair_getpublicpem(IntPtr keypair, IntPtr buffer);
        [DllImport(dllLocation, CallingConvention = CallingConvention.Cdecl)]
        public static extern void keypair_getpublicder(IntPtr keypair, IntPtr buffer);
        [DllImport(dllLocation, CallingConvention = CallingConvention.Cdecl)]
        public static extern IntPtr keypair_getpublickey(IntPtr keypair);
        [DllImport(dllLocation, CallingConvention = CallingConvention.Cdecl)]
        public static extern IntPtr keypair_getprivatekey(IntPtr keypair);
        [DllImport(dllLocation, CallingConvention = CallingConvention.Cdecl)]
        public static extern void keypair_sign_data(IntPtr keypair, IntPtr bufferin, IntPtr bufferout);

        [DllImport(dllLocation, CallingConvention = CallingConvention.Cdecl)]
        public static extern IntPtr keypairing_new();
        [DllImport(dllLocation, CallingConvention = CallingConvention.Cdecl)]
        public static extern void keypairing_delete(IntPtr keypairing);
        [DllImport(dllLocation, CallingConvention = CallingConvention.Cdecl)]
        public static extern void keypairing_set(IntPtr keypairing, IntPtr serviceAddress, string terminalAddress, IntPtr terminalCommitment, string serviceName, IntPtr serviceIdentityKey);
        [DllImport(dllLocation, CallingConvention = CallingConvention.Cdecl)]
        public static extern void keypairing_print(IntPtr keypairing);
        [DllImport(dllLocation, CallingConvention = CallingConvention.Cdecl)]
        public static extern void keypairing_log(IntPtr keypairing);
        [DllImport(dllLocation, CallingConvention = CallingConvention.Cdecl)]
        public static extern int keypairing_serialize_size(IntPtr keypairing);
        [DllImport(dllLocation, CallingConvention = CallingConvention.Cdecl)]
        public static extern int keypairing_serialize(IntPtr keypairing, byte[] buffer, int size);

        [DllImport(dllLocation, CallingConvention = CallingConvention.Cdecl)]
        public static extern IntPtr keyauth_new();
        [DllImport(dllLocation, CallingConvention = CallingConvention.Cdecl)]
        public static extern void keyauth_delete(IntPtr keyauth);
        [DllImport(dllLocation, CallingConvention = CallingConvention.Cdecl)]
        public static extern void keyauth_set(IntPtr keyauth, IntPtr serviceAddress, string terminalAddress, IntPtr terminalCommitment, IntPtr serviceIdentityKey);
        [DllImport(dllLocation, CallingConvention = CallingConvention.Cdecl)]
        public static extern void keyauth_print(IntPtr keyauth);
        [DllImport(dllLocation, CallingConvention = CallingConvention.Cdecl)]
        public static extern void keyauth_log(IntPtr keyauth);
        [DllImport(dllLocation, CallingConvention = CallingConvention.Cdecl)]
        public static extern int keyauth_serialize_size(IntPtr keyauth);
        [DllImport(dllLocation, CallingConvention = CallingConvention.Cdecl)]
        public static extern int keyauth_serialize(IntPtr keyauth, byte[] buffer, int size);

        [DllImport(dllLocation, CallingConvention = CallingConvention.Cdecl)]
        public static extern IntPtr buffer_new(int block_size);
        [DllImport(dllLocation, CallingConvention = CallingConvention.Cdecl)]
        public static extern void buffer_delete(IntPtr buffer);
        [DllImport(dllLocation, CallingConvention = CallingConvention.Cdecl)]
        public static extern int buffer_append(IntPtr buffer, byte[] toAppend, int size);
        [DllImport(dllLocation, CallingConvention = CallingConvention.Cdecl)]
        public static extern int buffer_append(IntPtr buffer, IntPtr toAppend, int size);
        [DllImport(dllLocation, CallingConvention = CallingConvention.Cdecl)]
        public static extern int buffer_append_string(IntPtr buffer, string data);
        [DllImport(dllLocation, CallingConvention = CallingConvention.Cdecl)]
        public static extern int buffer_append_buffer(IntPtr buffer, IntPtr appendFrom);
        [DllImport(dllLocation, CallingConvention = CallingConvention.Cdecl)]
        public static extern int buffer_append_buffer_lengthprepend(IntPtr buffer, IntPtr appendFrom);
        [DllImport(dllLocation, CallingConvention = CallingConvention.Cdecl)]
        public static extern int buffer_copy_lengthprepend(IntPtr bufferin, int start, IntPtr bufferout);
        [DllImport(dllLocation, CallingConvention = CallingConvention.Cdecl)]
        public static extern void buffer_truncate(IntPtr buffer, int reduce_by);
        [DllImport(dllLocation, CallingConvention = CallingConvention.Cdecl)]
        public static extern void buffer_print(IntPtr buffer);
        [DllImport(dllLocation, CallingConvention = CallingConvention.Cdecl)]
        public static extern void buffer_print_base64(IntPtr buffer);
        [DllImport(dllLocation, CallingConvention = CallingConvention.Cdecl)]
        public static extern void buffer_log(IntPtr buffer);
        [DllImport(dllLocation, CallingConvention = CallingConvention.Cdecl)]
        public static extern void buffer_log_base64(IntPtr buffer);
        [DllImport(dllLocation, CallingConvention = CallingConvention.Cdecl)]
        public static extern void buffer_clear(IntPtr buffer);
        [DllImport(dllLocation, CallingConvention = CallingConvention.Cdecl)]
        public static extern int buffer_copy_to_string(IntPtr buffer, byte[] str, int max_length);
        [DllImport(dllLocation, CharSet = CharSet.Ansi, CallingConvention = CallingConvention.Cdecl)]
        public static extern IntPtr buffer_copy_to_new_string(IntPtr buffer);
        [DllImport(dllLocation, CallingConvention = CallingConvention.Cdecl)]
        public static extern int buffer_get_pos(IntPtr buffer);
        [DllImport(dllLocation, CallingConvention = CallingConvention.Cdecl)]
        public static extern IntPtr buffer_get_buffer(IntPtr buffer);
        [DllImport(dllLocation, CallingConvention = CallingConvention.Cdecl)]
        public static extern void buffer_set_min_size(IntPtr buffer, int size);
        [DllImport(dllLocation, CallingConvention = CallingConvention.Cdecl)]
        public static extern int buffer_get_size(IntPtr buffer);
        [DllImport(dllLocation, CallingConvention = CallingConvention.Cdecl)]
        public static extern void buffer_set_pos(IntPtr buffer, int pos);
        [DllImport(dllLocation, CallingConvention = CallingConvention.Cdecl)]
        public static extern bool buffer_equals(IntPtr buffer, IntPtr compare);

        [DllImport(dllLocation, CallingConvention = CallingConvention.Cdecl)]
        public static extern IntPtr channel_connect(string name);
        [DllImport(dllLocation, CallingConvention = CallingConvention.Cdecl)]
        public static extern IntPtr channel_new();
        [DllImport(dllLocation, CallingConvention = CallingConvention.Cdecl)]
        public static extern void channel_delete(IntPtr channel);
        [DllImport(dllLocation, CallingConvention = CallingConvention.Cdecl)]
        public static extern bool channel_read(IntPtr channel, IntPtr buffer);
        [DllImport(dllLocation, CallingConvention = CallingConvention.Cdecl)]
        public static extern bool channel_write(IntPtr channel, byte[] data, int length);
        [DllImport(dllLocation, CallingConvention = CallingConvention.Cdecl)]
        public static extern bool channel_write_buffer(IntPtr channel, IntPtr buffer);
        [DllImport(dllLocation, CallingConvention = CallingConvention.Cdecl)]
        public static extern IntPtr channel_get_name(IntPtr channel);
        [DllImport(dllLocation, CallingConvention = CallingConvention.Cdecl)]
        public static extern void channel_get_url(IntPtr channel, IntPtr buffer);

        [DllImport(dllLocation, CallingConvention = CallingConvention.Cdecl)]
        public static extern IntPtr sigmakeyderiv_new();
        [DllImport(dllLocation, CallingConvention = CallingConvention.Cdecl)]
        public static extern void sigmakeyderiv_delete(IntPtr sigmakeyderiv);
        [DllImport(dllLocation, CallingConvention = CallingConvention.Cdecl)]
        public static extern void sigmakeyderiv_set(IntPtr sigmakeyderiv, IntPtr sharedSecret, IntPtr picoNonce, IntPtr serviceNonce);
        [DllImport(dllLocation, CallingConvention = CallingConvention.Cdecl)]
        public static extern void sigmakeyderiv_get_next_key(IntPtr sigmakeyderiv, IntPtr keyBytes, int length);

        [DllImport(dllLocation, CallingConvention = CallingConvention.Cdecl)]
        public static extern void base64_encode_buffer(IntPtr bufferin, IntPtr bufferout);
        [DllImport(dllLocation, CallingConvention = CallingConvention.Cdecl)]
        public static extern  void base64_encode_string(string stringin, IntPtr bufferout);
        [DllImport(dllLocation, CallingConvention = CallingConvention.Cdecl)]
        public static extern  void base64_encode_mem(IntPtr memin, int length, IntPtr bufferout);
        [DllImport(dllLocation, CallingConvention = CallingConvention.Cdecl)]
        public static extern  int base64_encode_size_max(int input);

        [DllImport(dllLocation, CallingConvention = CallingConvention.Cdecl)]
        public static extern  void base64_decode_buffer(IntPtr bufferin, IntPtr bufferout);
        [DllImport(dllLocation, CallingConvention = CallingConvention.Cdecl)]
        public static extern  void base64_decode_string(string stringin, IntPtr bufferout);
        [DllImport(dllLocation, CallingConvention = CallingConvention.Cdecl)]
        public static extern  int base64_decode_size_max(int input);

        [DllImport(dllLocation, CallingConvention = CallingConvention.Cdecl)]
        public static extern  IntPtr json_new();
        [DllImport(dllLocation, CallingConvention = CallingConvention.Cdecl)]
        public static extern  void json_delete(IntPtr json);
        [DllImport(dllLocation, CallingConvention = CallingConvention.Cdecl)] 
        public static extern void json_add_string(IntPtr json, string key, string value);
        [DllImport(dllLocation, CallingConvention = CallingConvention.Cdecl)] 
        public static extern void json_add_buffer(IntPtr json, string key, IntPtr value);
        [DllImport(dllLocation, CallingConvention = CallingConvention.Cdecl)]
        public static extern  void json_add_decimal(IntPtr json, string key, double value);
        [DllImport(dllLocation, CallingConvention = CallingConvention.Cdecl)]
        public static extern  void json_add_sublist(IntPtr json, string key, IntPtr sublist);
        [DllImport(dllLocation, CallingConvention = CallingConvention.Cdecl)]
        public static extern  int json_serialize_size(IntPtr json);
        [DllImport(dllLocation, CallingConvention = CallingConvention.Cdecl)]
        public static extern int json_serialize(IntPtr json, byte[] buffer, int size);
        [DllImport(dllLocation, CallingConvention = CallingConvention.Cdecl)]
        public static extern  int json_serialize_buffer(IntPtr json, IntPtr buffer);
        [DllImport(dllLocation, CallingConvention = CallingConvention.Cdecl)]
        public static extern bool json_deserialize_string(IntPtr json, string json_string, int length);
        [DllImport(dllLocation, CallingConvention = CallingConvention.Cdecl)]
        public static extern  bool json_deserialize_buffer(IntPtr json, IntPtr buffer);
        [DllImport(dllLocation, CallingConvention = CallingConvention.Cdecl)]
        public static extern  void json_print(IntPtr json);
        [DllImport(dllLocation, CallingConvention = CallingConvention.Cdecl)]
        public static extern  void json_log(IntPtr json);
        [DllImport(dllLocation, CallingConvention = CallingConvention.Cdecl)]
        public static extern  int json_get_type(IntPtr json, string key);
        [DllImport(dllLocation, CallingConvention = CallingConvention.Cdecl)]
        public static extern  IntPtr json_get_string(IntPtr json, string key);
        [DllImport(dllLocation, CallingConvention = CallingConvention.Cdecl)]
        public static extern  double json_get_decimal(IntPtr json, string key);

        [DllImport(dllLocation, CallingConvention = CallingConvention.Cdecl)]
        public static extern void cryptosupport_getpublicpem(IntPtr eckey, IntPtr buffer);
        [DllImport(dllLocation, CallingConvention = CallingConvention.Cdecl)]
        public static extern  void cryptosupport_getpublicder(IntPtr eckey, IntPtr buffer);
        [DllImport(dllLocation, CallingConvention = CallingConvention.Cdecl)]
        public static extern  bool cryptosupport_generate_mac(IntPtr macKey, IntPtr data, IntPtr bufferout);
        [DllImport(dllLocation, CallingConvention = CallingConvention.Cdecl)]
        public static extern  bool cryptosupport_verify_signature(IntPtr publickey, IntPtr bufferin, IntPtr sigin);
        [DllImport(dllLocation, CallingConvention = CallingConvention.Cdecl)]
        public static extern  bool cryptosupport_encrypt(IntPtr key, IntPtr iv, IntPtr bufferin, IntPtr encryptedout);
        [DllImport(dllLocation, CallingConvention = CallingConvention.Cdecl)]
        public static extern  bool cryptosupport_decrypt(IntPtr key, IntPtr iv, IntPtr bufferin, IntPtr cleartextout);
        [DllImport(dllLocation, CallingConvention = CallingConvention.Cdecl)]
        public static extern  void cryptosupport_generate_iv(IntPtr iv);
        [DllImport(dllLocation, CallingConvention = CallingConvention.Cdecl)]
        public static extern  bool cryptosupport_generate_sha256(IntPtr bufferin, IntPtr bufferout);
        [DllImport(dllLocation, CallingConvention = CallingConvention.Cdecl)]
        public static extern  bool cryptosupport_generate_commitment(IntPtr publickey, IntPtr commitment);
        [DllImport(dllLocation, CallingConvention = CallingConvention.Cdecl)]
        public static extern  bool cryptosupport_generate_commitment_base64(IntPtr publickey, IntPtr commitment);
        [DllImport(dllLocation, CallingConvention = CallingConvention.Cdecl)]
        public static extern  IntPtr cryptosupport_read_base64_buffer_public_key(IntPtr keybuffer);
        [DllImport(dllLocation, CallingConvention = CallingConvention.Cdecl)]
        public static extern  IntPtr cryptosupport_read_base64_string_public_key(string keystring);
        [DllImport(dllLocation, CallingConvention = CallingConvention.Cdecl)]
        public static extern  IntPtr cryptosupport_read_buffer_public_key(IntPtr keybuffer);
        [DllImport(dllLocation, CallingConvention = CallingConvention.Cdecl)]
        public static extern bool cryptosupport_encrypt_iv_base64(IntPtr key, IntPtr bufferin, IntPtr encryptedout);
        [DllImport(dllLocation, CallingConvention = CallingConvention.Cdecl)]
        public static extern bool cryptosupport_decrypt_iv_base64(IntPtr key, IntPtr bufferin, IntPtr cleartextout);
        [DllImport(dllLocation, CallingConvention = CallingConvention.Cdecl)]
        public static extern bool cryptosupport_generate_symmetric_key(IntPtr key, int size);
        
        [DllImport(dllLocation, CallingConvention = CallingConvention.Cdecl)]
        public static extern void keyagreement_generate_secret(IntPtr vEphemPriv, IntPtr pEphemPub, IntPtr sharedSecretOut);

        [DllImport(dllLocation, CallingConvention = CallingConvention.Cdecl)]
        public static extern bool sigmaverifier(IntPtr shared, IntPtr channel, IntPtr authorizedUsers, string extraData, IntPtr returnedStoredData, IntPtr localSymmetricKey);

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        public delegate bool QrCallbackFunctionInternal(string qrData, IntPtr localData);

        [DllImport(dllLocation, CallingConvention = CallingConvention.Cdecl)]
        public static extern bool pair(IntPtr shared, string servicename, string extraData, IntPtr returnedStoredData, QrCallbackFunctionInternal qrCallback, IntPtr data);
        [DllImport(dllLocation, CallingConvention = CallingConvention.Cdecl)]
        public static extern bool pair_send_username_loop(IntPtr shared, string servicename, string extraData, string username, IntPtr returnedStoredData, QrCallbackFunctionInternal qrCallback, IntPtr data, int loop_verifier);
        [DllImport(dllLocation, CallingConvention = CallingConvention.Cdecl)]
        public static extern bool auth(IntPtr shared, IntPtr authorizedUsers, IntPtr returnedStoredData, QrCallbackFunctionInternal qrCallback, IntPtr data, IntPtr localSymmetricKey);
        [DllImport(dllLocation, CallingConvention = CallingConvention.Cdecl)]
        public static extern bool pair_loop(IntPtr shared, string servicename, string extraData, IntPtr returnedStoredData, QrCallbackFunctionInternal qrCallback, IntPtr data, int loopVerifier);
        
    }

    public class PicoBuffer
    {
        private IntPtr handle;

        public IntPtr getIntPtr()
        {
            return handle;
        }

        public PicoBuffer(int block_size)
        {
            handle = PicoDLL.buffer_new(block_size);
        }

        public PicoBuffer(IntPtr ptr)
        {
            this.handle = ptr;
        }

        public void delete()
        {
            PicoDLL.buffer_delete(handle);
        }

        public int append(byte[] data)
        {
            return PicoDLL.buffer_append(handle, data, data.Length);
        }

        public int append(IntPtr data, int len)
        {
            return PicoDLL.buffer_append(handle, data, len);
        }

        public int append(string data)
        {
            return PicoDLL.buffer_append_string(handle, data);
        }

        public int append(PicoBuffer buff)
        {
            return PicoDLL.buffer_append_buffer(handle, buff.getIntPtr());
        }

        public int append_lengthprepend(PicoBuffer buff)
        {
            return PicoDLL.buffer_append_buffer_lengthprepend(handle, buff.getIntPtr());
        }

        public void truncate(int reduce_by)
        {
            PicoDLL.buffer_truncate(handle, reduce_by);
        }

        public void print(bool base64 = false)
        {
            if (base64)
                PicoDLL.buffer_print_base64(handle);
            else
                PicoDLL.buffer_print(handle);
        }

        public void log(bool base64 = false)
        {
            if (base64)
                PicoDLL.buffer_log_base64(handle);
            else
                PicoDLL.buffer_log(handle);
        }

        public void clear()
        {
            PicoDLL.buffer_clear(handle);
        }

        public int copy_to_array(byte[] str, int max_length = -1)
        {
            if (max_length == -1)
                max_length = str.Length;
            return PicoDLL.buffer_copy_to_string(handle, str, max_length);
        }

        public string to_string()
        {
            // TODO free
            IntPtr ptr = PicoDLL.buffer_copy_to_new_string(handle);
            return Marshal.PtrToStringAnsi(ptr);
        }

        public int get_pos()
        {
            return PicoDLL.buffer_get_pos(handle);
        }

        public IntPtr getRawBuffer()
        {
            return PicoDLL.buffer_get_buffer(handle);
        }

        public void set_min_size(int size)
        {
            PicoDLL.buffer_set_min_size(handle, size);
        }

        public int get_size()
        {
            return PicoDLL.buffer_get_size(handle);
        }

        public void set_pos(int pos)
        {
            PicoDLL.buffer_set_pos(handle, pos);
        }

        public bool equals(PicoBuffer buff)
        {
            return PicoDLL.buffer_equals(handle, buff.getIntPtr());
        }
        
        public int copy_lengthprepend(int start, PicoBuffer bufferout)
        {
            return PicoDLL.buffer_copy_lengthprepend(handle, start, bufferout.getIntPtr());
        }

    
    }
    public class Users
    {
        private IntPtr handle;

        public IntPtr getIntPtr()
        {
            return handle;
        }

        public Users()
        {
            handle = PicoDLL.users_new();
        }

        public void delete()
        {
            PicoDLL.users_delete(handle);
        }

        public int add_user(string name, IntPtr key, PicoBuffer symmetric_key)
        {
            return PicoDLL.users_add_user(handle, name, key, symmetric_key.getIntPtr());
        }

        public int export(string file)
        {
            return PicoDLL.users_export(handle, file);
        }

        public int load(string file)
        {
            return PicoDLL.users_load(handle, file);
        }

        public PicoBuffer search_by_key(IntPtr key)
        {
            return new PicoBuffer(PicoDLL.users_search_by_key(handle, key));
        }

        public void delete_all()
        {
            PicoDLL.users_delete_all(handle);
        }

        public void print()
        {
            PicoDLL.users_print(handle);
        }

        public void move_list(Users to)
        {
            PicoDLL.users_move_list(handle, to.getIntPtr());
        }

        public int filter_by_name(string name, Users result)
        {
            return PicoDLL.users_filter_by_name(handle, name, result.getIntPtr());
        }

        public PicoBuffer search_symmetrickey_by_key(IntPtr picoIdentityPublicKey) {
            return new PicoBuffer(PicoDLL.users_search_symmetrickey_by_key(handle, picoIdentityPublicKey));
        }

    }
    public class Nonce
    {
        private IntPtr handle;
        public IntPtr getIntPtr() 
        {
            return handle;
        }

        public Nonce()
        {
            handle = PicoDLL.nonce_new();
        }

        public Nonce(IntPtr ptr)
        {
            this.handle = ptr;
        }

        public void delete()
        {
            PicoDLL.nonce_delete(handle);
        }

        public void set_buffer(PicoBuffer buff)
        {
            PicoDLL.nonce_set_buffer(handle, buff.getIntPtr());
        }

        public void generate_random()
        {
            PicoDLL.nonce_generate_random(handle);
        }

        public IntPtr get_buffer()
        {
            return PicoDLL.nonce_get_buffer(handle);
        }

        public int get_length()
        {
            return PicoDLL.nonce_get_length(handle);
        }
    }

    public class Shared
    {
        private IntPtr handle;

        public IntPtr getIntPtr()
        {
            return handle;
        }

        public Shared()
        {
            handle = PicoDLL.shared_new();
        }

        public void delete()
        {
            PicoDLL.shared_delete(handle);
        }

        public void generate_shared_secret()
        {
            PicoDLL.shared_generate_shared_secrets(handle);
        }

        public void load_or_generate_keys(string key_public, string key_private)
        {
            PicoDLL.shared_load_or_generate_keys(handle, key_public, key_private);
        }

        public Nonce get_service_nonce()
        {
            return new Nonce(PicoDLL.shared_get_service_nonce(handle));
        }

        public Nonce get_pico_nonce()
        {
            return new Nonce(PicoDLL.shared_get_pico_nonce(handle));
        }

        public KeyPair get_service_identity_key()
        {
            return new KeyPair(PicoDLL.shared_get_service_identity_key(handle));
        }

        public KeyPair get_service_ephemeral_key()
        {
            return new KeyPair(PicoDLL.shared_get_service_ephemeral_key(handle));
        }

        public void set_pico_identity_public_key(IntPtr picoIdentityPublicKey)
        {
            PicoDLL.shared_set_pico_identity_public_key(handle, picoIdentityPublicKey);
        }

        public IntPtr get_pico_identity_public_key()
        {
            return PicoDLL.shared_get_pico_identity_public_key(handle);
        }

        public void set_pico_ephemeral_public_key(IntPtr picoEphemeralPublicKey)
        {
            PicoDLL.shared_set_pico_ephemeral_public_key(handle, picoEphemeralPublicKey);
        }

        public IntPtr get_pico_ephemeral_public_key()
        {
            return PicoDLL.shared_get_pico_ephemeral_public_key(handle);
        }

        public PicoBuffer get_prover_enc_key()
        {
            return new PicoBuffer(PicoDLL.shared_get_prover_enc_key(handle));
        }

        public PicoBuffer get_verifier_enc_key()
        {
            return new PicoBuffer(PicoDLL.shared_get_verifier_enc_key(handle));
        }

        public PicoBuffer get_prover_mac_key()
        {
            return new PicoBuffer(PicoDLL.shared_get_prover_mac_key(handle));
        }

        public PicoBuffer get_verifier_mac_key()
        {
            return new PicoBuffer(PicoDLL.shared_get_verifier_mac_key(handle));
        }

    }

    public class KeyPair
    {
        private IntPtr handle;

        public KeyPair()
        {
            handle = PicoDLL.keypair_new();
        }

        public KeyPair(IntPtr ptr)
        {
            this.handle = ptr;
        }

        public IntPtr getIntPtr()
        {
            return handle;
        }

        public void delete()
        {
            PicoDLL.keypair_delete(handle);
        }

        public void generate()
        {
            PicoDLL.keypair_generate(handle);
        }

        public void export(string key_public, string key_private)
        {
            PicoDLL.keypair_export(handle, key_public, key_private);
        }

        public bool import(string key_public, string key_private)
        {
            return PicoDLL.keypair_import(handle, key_public, key_private);
        }

        public void clear_keys()
        {
            PicoDLL.keypair_clear_keys(handle);
        }

        public void getpublicpem(PicoBuffer buff)
        {
            PicoDLL.keypair_getpublicpem(handle, buff.getIntPtr());
        }

        public void getpublicder(PicoBuffer buff)
        {
            PicoDLL.keypair_getpublicder(handle, buff.getIntPtr());
        }

        public IntPtr getpublickey()
        {
            return PicoDLL.keypair_getpublickey(handle);
        }

        public IntPtr getprivatekey()
        {
            return PicoDLL.keypair_getprivatekey(handle);
        }

        public void sign_data(PicoBuffer bufferin, PicoBuffer bufferout)
        {
            PicoDLL.keypair_sign_data(handle, bufferin.getIntPtr(), bufferout.getIntPtr());
        }
    }

    public class KeyPairing
    {
        IntPtr handle;

        public KeyPairing()
        {
            handle = PicoDLL.keypairing_new();
        }

        public void delete()
        {
            PicoDLL.keypairing_delete(handle);
        }

        public void set(PicoBuffer serviceAddress, string terminalAddress, PicoBuffer terminalCommitment, string serviceName, KeyPair serviceIdentityKey)
        {
            IntPtr terminalCommitmentPtr = IntPtr.Zero;
            if (terminalCommitment != null)
                terminalCommitmentPtr = terminalCommitment.getIntPtr();
            PicoDLL.keypairing_set(handle, serviceAddress.getIntPtr(), terminalAddress, terminalCommitmentPtr, serviceName, serviceIdentityKey.getIntPtr());
        }

        public void print()
        {
            PicoDLL.keypairing_print(handle);
        }

        public void log()
        {
            PicoDLL.keypairing_log(handle);
        }

        public int serialize_size()
        {
            return PicoDLL.keypairing_serialize_size(handle);
        }

        public int serialize(byte[] buffer)
        {
            return PicoDLL.keypairing_serialize(handle, buffer, buffer.Length);
        }

    }

    public class KeyAuth
    {
        IntPtr handle;

        public KeyAuth()
        {
            handle = PicoDLL.keyauth_new();
        }

        public void delete()
        {
            PicoDLL.keyauth_delete(handle);
        }

        public void set(PicoBuffer serviceAddress, string terminalAddress, PicoBuffer terminalCommitment, KeyPair serviceIdentityKey)
        {
            IntPtr terminalCommitmentPtr = IntPtr.Zero;
            if (terminalCommitment != null)
                terminalCommitmentPtr = terminalCommitment.getIntPtr();
            PicoDLL.keyauth_set(handle, serviceAddress.getIntPtr(), terminalAddress, terminalCommitmentPtr, serviceIdentityKey.getIntPtr());
        }

        public void print()
        {
            PicoDLL.keyauth_print(handle);
        }

        public void log()
        {
            PicoDLL.keyauth_log(handle);
        }

        public int serialize_size()
        {
            return PicoDLL.keyauth_serialize_size(handle);
        }

        public int serialize(byte[] data)
        {
            return PicoDLL.keyauth_serialize(handle, data, data.Length);
        }
    }



    public class Channel
    {
        private IntPtr handle;

        public IntPtr getIntPtr()
        {
            return handle;
        }

        private Channel(IntPtr handle)
        {
            this.handle = handle;
        }

        public Channel()
        {
            handle = PicoDLL.channel_new();
        }

        public void delete()
        {
            PicoDLL.channel_delete(handle);
        }

        public static Channel connect(string name)
        {
            return new Channel(PicoDLL.channel_connect(name));
        }

        public bool read(PicoBuffer buff)
        {
            return PicoDLL.channel_read(handle, buff.getIntPtr());
        }

        public bool write(byte[] data, int length)
        {
            return PicoDLL.channel_write(handle, data, length);
        }

        public bool write_buffer(PicoBuffer buff)
        {
            return PicoDLL.channel_write_buffer(handle, buff.getIntPtr());
        }

        public string get_name()
        {
            IntPtr nameptr = PicoDLL.channel_get_name(handle);
            return Marshal.PtrToStringAnsi(nameptr);
        }

        public void get_url(PicoBuffer buff)
        {
            PicoDLL.channel_get_url(handle, buff.getIntPtr());
        }
    }

    public static class Sigma
    {
        public static bool verify(Shared shared, Channel channel, Users authorizedUsers, string extraData, PicoBuffer returnedStoredData, PicoBuffer localSymmetricKey) {
            IntPtr usersPtr = IntPtr.Zero;
            if (authorizedUsers != null)
                usersPtr = authorizedUsers.getIntPtr();
            IntPtr storedDataPtr = IntPtr.Zero;
            if (returnedStoredData != null)
                storedDataPtr = returnedStoredData.getIntPtr();
            IntPtr localSymmetricKeyPtr = IntPtr.Zero;
            if (localSymmetricKey != null)
                localSymmetricKeyPtr = localSymmetricKey.getIntPtr();
            return PicoDLL.sigmaverifier(shared.getIntPtr(), channel.getIntPtr(), usersPtr, extraData, storedDataPtr, localSymmetricKeyPtr);
        }
    }

    public static class Base64
    {
        public static void encode(PicoBuffer bufferin, PicoBuffer bufferout)
        {
            PicoDLL.base64_encode_buffer(bufferin.getIntPtr(), bufferout.getIntPtr());
        }

        public static void encode(string stringin, PicoBuffer bufferout)
        {
            PicoDLL.base64_encode_string(stringin, bufferout.getIntPtr());
        }
        
        public static void encode(IntPtr memin, int length, PicoBuffer bufferout)
        {
            PicoDLL.base64_encode_mem(memin, length, bufferout.getIntPtr());
        }
                
        public static int encode_size_max(int input)
        {
            return PicoDLL.base64_encode_size_max(input);
        }
                

        public static void decode(PicoBuffer bufferin, PicoBuffer bufferout)
        {
            PicoDLL.base64_decode_buffer(bufferin.getIntPtr(), bufferout.getIntPtr());
        }
        
        public static void decode(string stringin, PicoBuffer bufferout)
        {
            PicoDLL.base64_decode_string(stringin, bufferout.getIntPtr());
        }
        
        public static int decode_size_max(int input)
        {
            return PicoDLL.base64_decode_size_max(input);
        }
    }

    public class SigmaKeyDeriv
    {
        private IntPtr handle;

        public IntPtr getIntPtr()
        {
            return handle;
        }

        public SigmaKeyDeriv() 
        {
            handle = PicoDLL.sigmakeyderiv_new();
        }

        public void delete() 
        {
            PicoDLL.sigmakeyderiv_delete(handle);
        }

        public void set(PicoBuffer sharedSecret, Nonce picoNonce, Nonce serviceNonce) 
        {
            PicoDLL.sigmakeyderiv_set(handle, sharedSecret.getIntPtr(), picoNonce.getIntPtr(), serviceNonce.getIntPtr());
        }

        public void get_next_key(PicoBuffer keyBytes, int length)
        {
            PicoDLL.sigmakeyderiv_get_next_key(handle, keyBytes.getIntPtr(), length);
        }
    }

    public class Json
    {
        private IntPtr handle;

        public IntPtr getIntPtr()
        {
            return handle;
        }

        public Json() { 
            handle = PicoDLL.json_new();
        }

        public void delete()
        {
            PicoDLL.json_delete(handle);
        }

        public void add(string key, string value)
        {
            PicoDLL.json_add_string(handle, key, value);
        }

        public void add(string key, PicoBuffer value)
        {
            PicoDLL.json_add_buffer(handle, key, value.getIntPtr());
        }

        public void add(string key, double value)
        {
            PicoDLL.json_add_decimal(handle, key, value);
        }

        public void add(string key, Json sublist)
        {
            PicoDLL.json_add_sublist(handle, key, sublist.getIntPtr());
        }

        public int serialize_size()
        {
            return PicoDLL.json_serialize_size(handle);
        }

        public int serialize(byte[] buffer, int size = -1)
        {
            if (size == -1)
                size = buffer.Length;
            return PicoDLL.json_serialize(handle, buffer, size);
        }

        public int serialize(PicoBuffer buffer)
        {
            return PicoDLL.json_serialize_buffer(handle, buffer.getIntPtr());
        }

        public bool deserialize(string str)
        {
            return PicoDLL.json_deserialize_string(handle, str, str.Length);
        }

        public bool deserialize(PicoBuffer buff)
        {
            return PicoDLL.json_deserialize_buffer(handle, buff.getIntPtr());
        }

        public string get_string(string key)
        {
            IntPtr ptr = PicoDLL.json_get_string(handle, key);
            return Marshal.PtrToStringAnsi(ptr);
        }

        public double get_decimal(string key)
        {
            return PicoDLL.json_get_decimal(handle, key);
        }
    }

    public static class CryptoSupport
    {
        public const int AESKEY_SIZE = 16;

        public static void getpublicpem(IntPtr eckey, PicoBuffer buffer)
        {
            PicoDLL.cryptosupport_getpublicpem(eckey, buffer.getIntPtr());
        }

        public static void getpublicder(IntPtr eckey, PicoBuffer buffer)
        {
            PicoDLL.cryptosupport_getpublicder(eckey, buffer.getIntPtr());
        }

        public static bool generate_mac(PicoBuffer macKey, PicoBuffer data, PicoBuffer bufferout)
        {
            return PicoDLL.cryptosupport_generate_mac(macKey.getIntPtr(), data.getIntPtr(), bufferout.getIntPtr());
        }

        public static bool verify_signature(IntPtr publickey, PicoBuffer bufferin, PicoBuffer sigin)
        {
            return PicoDLL.cryptosupport_verify_signature(publickey, bufferin.getIntPtr(), sigin.getIntPtr());
        }

        public static bool encrypt(PicoBuffer key, PicoBuffer iv, PicoBuffer bufferin, PicoBuffer encryptedout)
        {
            return PicoDLL.cryptosupport_encrypt(key.getIntPtr(), iv.getIntPtr(), bufferin.getIntPtr(), encryptedout.getIntPtr());
        }

        public static bool decrypt(PicoBuffer key, PicoBuffer iv, PicoBuffer bufferin, PicoBuffer cleartextout)
        {
            return PicoDLL.cryptosupport_decrypt(key.getIntPtr(), iv.getIntPtr(), bufferin.getIntPtr(), cleartextout.getIntPtr());
        }

        public static void generate_iv(PicoBuffer iv)
        {
            PicoDLL.cryptosupport_generate_iv(iv.getIntPtr());
        }

        public static bool generate_sha256(PicoBuffer bufferin, PicoBuffer bufferout)
        {
            return PicoDLL.cryptosupport_generate_sha256(bufferin.getIntPtr(), bufferout.getIntPtr());
        }

        public static bool generate_commitment(IntPtr publickey, PicoBuffer commitment)
        {
            return PicoDLL.cryptosupport_generate_commitment(publickey, commitment.getIntPtr());
        }

        public static bool generate_commitment_base64(IntPtr publickey, PicoBuffer commitment)
        {
            return PicoDLL.cryptosupport_generate_commitment_base64(publickey, commitment.getIntPtr());
        }

        public static IntPtr read_base64_buffer_public_key(PicoBuffer keybuffer)
        {
            return PicoDLL.cryptosupport_read_base64_buffer_public_key(keybuffer.getIntPtr());
        }

        public static IntPtr read_base64_string_public_key(string keystring)
        {
            return PicoDLL.cryptosupport_read_base64_string_public_key(keystring);
        }

        public static IntPtr read_buffer_public_key(PicoBuffer keybuffer)
        {
            return PicoDLL.cryptosupport_read_buffer_public_key(keybuffer.getIntPtr());
        }

        public static bool encrypt_iv_base64(PicoBuffer key, PicoBuffer bufferin, PicoBuffer encryptedout) 
        {
            return PicoDLL.cryptosupport_encrypt_iv_base64(key.getIntPtr(), bufferin.getIntPtr(), encryptedout.getIntPtr());
        }

        public static bool decrypt_iv_base64(PicoBuffer key, PicoBuffer bufferin, PicoBuffer cleartextout) 
        {
            return PicoDLL.cryptosupport_decrypt_iv_base64(key.getIntPtr(), bufferin.getIntPtr(), cleartextout.getIntPtr());
        }
                
        public static bool generate_symmetric_key(PicoBuffer key, int size) 
        {
            return PicoDLL.cryptosupport_generate_symmetric_key(key.getIntPtr(), size);
        }
    }

    public static class KeyAgreement
    {
        public static void generate_secret(IntPtr vEphemPriv, IntPtr pEphemPub, PicoBuffer sharedSecretOut)
        {
            PicoDLL.keyagreement_generate_secret(vEphemPriv, pEphemPub, sharedSecretOut.getIntPtr());
        }
    }

    public static class Auth
    {
        public delegate bool QrCallback(string qrData, object localData);

        public static bool pair(Shared shared, string serviceName, string extraData, PicoBuffer returnedStoredData, QrCallback qrCallback, object data)
        {
            IntPtr sharedPtr = IntPtr.Zero;
            if (shared != null)
                sharedPtr = shared.getIntPtr();
            IntPtr storedDataPtr = IntPtr.Zero;
            if (returnedStoredData != null)
                storedDataPtr = returnedStoredData.getIntPtr();

            PicoDLL.QrCallbackFunctionInternal internalDelegate = delegate(string qrData, IntPtr intPtr)
            {
                return qrCallback(qrData, ((GCHandle)intPtr).Target);
            };

            return PicoDLL.pair(sharedPtr, serviceName, extraData, storedDataPtr, internalDelegate, (IntPtr)GCHandle.Alloc(data));
        }

        public static bool pair_send_username_loop(Shared shared, string serviceName, string extraData, string username, PicoBuffer returnedStoredData, QrCallback qrCallback, object data, int loopVerifier)
        {
            IntPtr sharedPtr = IntPtr.Zero;
            if (shared != null)
                sharedPtr = shared.getIntPtr();
            IntPtr storedDataPtr = IntPtr.Zero;
            if (returnedStoredData != null)
                storedDataPtr = returnedStoredData.getIntPtr();

            PicoDLL.QrCallbackFunctionInternal internalDelegate = delegate(string qrData, IntPtr intPtr)
            {
                return qrCallback(qrData, ((GCHandle)intPtr).Target);
            };

            return PicoDLL.pair_send_username_loop(sharedPtr, serviceName, extraData, username, storedDataPtr, internalDelegate, (IntPtr)GCHandle.Alloc(data), loopVerifier);
        }

        public static bool auth(Shared shared, Users authorizedUsers, PicoBuffer returnedStoredData, QrCallback qrCallback, object data, PicoBuffer localSymmetricKey)
        {
            IntPtr sharedPtr = IntPtr.Zero;
            if (shared != null)
                sharedPtr = shared.getIntPtr();
            IntPtr usersPtr = IntPtr.Zero;
            if (authorizedUsers != null)
                usersPtr = authorizedUsers.getIntPtr();
            IntPtr storedDataPtr = IntPtr.Zero;
            if (returnedStoredData != null)
                storedDataPtr = returnedStoredData.getIntPtr();
            IntPtr localSymmetricKeyPtr = IntPtr.Zero;
            if (localSymmetricKey != null)
                localSymmetricKeyPtr = localSymmetricKey.getIntPtr();
            
            PicoDLL.QrCallbackFunctionInternal internalDelegate = delegate(string qrData, IntPtr intPtr)
            {
                return qrCallback(qrData, ((GCHandle)intPtr).Target);
            };

            return PicoDLL.auth(sharedPtr, usersPtr, storedDataPtr, internalDelegate, (IntPtr)GCHandle.Alloc(data), localSymmetricKeyPtr);
        }

        public static bool pair_loop(Shared shared, string servicename, string extraData, PicoBuffer returnedStoredData, QrCallback qrCallback, object data, int loopVerifier)
        {
            IntPtr sharedPtr = IntPtr.Zero;
            if (shared != null)
                sharedPtr = shared.getIntPtr();
            IntPtr storedDataPtr = IntPtr.Zero;
            if (returnedStoredData != null)
                storedDataPtr = returnedStoredData.getIntPtr();

            PicoDLL.QrCallbackFunctionInternal internalDelegate = delegate(string qrData, IntPtr intPtr)
            {
                return qrCallback(qrData, ((GCHandle)intPtr).Target);
            };

            return PicoDLL.pair_loop(sharedPtr, servicename, extraData, storedDataPtr, internalDelegate, (IntPtr)GCHandle.Alloc(data), loopVerifier);
        }

    }
}
