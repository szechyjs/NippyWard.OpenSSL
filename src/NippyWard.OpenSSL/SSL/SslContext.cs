using System;
using System.Collections.Generic;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Diagnostics;
using System.Reflection;

using NippyWard.OpenSSL.X509;
using NippyWard.OpenSSL.Keys;
using NippyWard.OpenSSL.Interop;
using NippyWard.OpenSSL.Interop.SafeHandles.SSL;
using NippyWard.OpenSSL.Collections;
using NippyWard.OpenSSL.Interop.SafeHandles;
using NippyWard.OpenSSL.Interop.Wrappers;
using NippyWard.OpenSSL.Interop.SafeHandles.X509;

namespace NippyWard.OpenSSL.SSL
{
    public class SslContext : OpenSslBase, IDisposable
    {
        //pin callback delegates
        private readonly SessionCallback? _sessionCallback;
        private readonly VerifyCertificateCallback? _verifyCertificateCallback;
        private readonly ClientCertificateCallback? _clientCertificateCallback;

        #region native handles
        internal readonly SafeSslContextHandle _sslContextHandle;
        internal SafeSslSessionHandle? _sessionHandle;
        #endregion

        #region managed callbacks
        private readonly RemoteCertificateValidationHandler? _remoteCertificateValidationHandler;
        private readonly ClientCertificateCallbackHandler? _clientCertificateCallbackHandler;
        #endregion

        private readonly bool _isServer;

        public static SslContext CreateSslContext
        (
            SslOptions sslOptions,
            bool isServer
        )
            => CreateSslContext
            (
                sslStrength: sslOptions.SslStrength,
                sslProtocol: sslOptions.SslProtocol,
                certificateStore: sslOptions.CertificateStore,
                certificate: sslOptions.Certificate,
                privateKey: sslOptions.PrivateKey,
                clientCertificateCallbackHandler: sslOptions.ClientCertificateCallbackHandler,
                remoteCertificateValidationHandler: sslOptions.RemoteCertificateValidationHandler,
                ciphers: sslOptions.Ciphers,
                isServer
            );

        public static SslContext CreateSslContext
        (
            SslStrength sslStrength,
            SslProtocol sslProtocol,
            X509Store? certificateStore,
            X509Certificate? certificate,
            PrivateKey? privateKey,
            ClientCertificateCallbackHandler? clientCertificateCallbackHandler,
            RemoteCertificateValidationHandler? remoteCertificateValidationHandler,
            IEnumerable<string>? ciphers,
            bool isServer
        )
        {
            SafeSslContextHandle? sslContextHandle = null;

            try
            {
                sslContextHandle = SslContext.CreateSslContexthandle
                (
                    sslStrength: sslStrength,
                    sslProtocol: sslProtocol,
                    certificateStore: certificateStore,
                    certificate: certificate,
                    privateKey: privateKey,
                    ciphers: ciphers,
                    isServer
                );

                return new SslContext
                (
                    isServer,
                    sslContextHandle,
                    clientCertificateCallbackHandler,
                    remoteCertificateValidationHandler
                );
            }
            catch (Exception)
            {
                sslContextHandle?.Dispose();

                throw;
            }
        }

        private SslContext
        (
            bool isServer,
            SafeSslContextHandle sslContextHandle,
            ClientCertificateCallbackHandler? clientCertificateCallbackHandler = null,
            RemoteCertificateValidationHandler? remoteCertificateValidationHandler = null
        )
        {
            //enable session caching
            SSLWrapper.SSL_CTX_ctrl
            (
                sslContextHandle,
                Native.SSL_CTRL_SET_SESS_CACHE_MODE,
                (int)Native.SSL_SESS_CACHE_CLIENT | Native.SSL_SESS_CACHE_NO_INTERNAL,
                IntPtr.Zero
            );

            //enable session callback
            SSLWrapper.SSL_CTX_sess_set_new_cb(sslContextHandle, (this._sessionCallback = new SessionCallback(this.SessionCallback)));

            //enable certificate validation
            if (remoteCertificateValidationHandler is not null)
            {
                this._remoteCertificateValidationHandler = remoteCertificateValidationHandler;
                SSLWrapper.SSL_CTX_set_verify
                (
                    sslContextHandle,
                    (int)VerifyMode.SSL_VERIFY_PEER,
                    (this._verifyCertificateCallback = new VerifyCertificateCallback(this.RemoteCertificateValidationCallback))
                );
            }
            else
            {
                //this should be default, but set it anyways
                SSLWrapper.SSL_CTX_set_verify
                (
                    sslContextHandle,
                    (int)VerifyMode.SSL_VERIFY_NONE,
                    null
                );
            }

            //enable client certificate request
            if (clientCertificateCallbackHandler is not null)
            {
                if (isServer)
                {
                    throw new NotSupportedException("A client certificate can only get returned from client mode");
                }

                this._clientCertificateCallbackHandler = clientCertificateCallbackHandler;
                SSLWrapper.SSL_CTX_set_client_cert_cb
                (
                    sslContextHandle,
                    (this._clientCertificateCallback = new ClientCertificateCallback(this.ClientCertificateRequestCallback))
                );
            }

            this._sslContextHandle = sslContextHandle;
            this._isServer = isServer;
        }

        //disposal only possible through finalizer (!!!)
        //there is no way to know when the safehandle has been used
        //multiple times
        ~SslContext()
        {
            this.Dispose(false);
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="sslStrength"></param>
        /// <param name="sslProtocol"></param>
        /// <param name="certificateStore">
        /// In client mode: the trusted CA's.
        /// In server mode: the CA's to validate the client certificate.
        /// </param>
        /// <param name="certificate"></param>
        /// <param name="privateKey"></param>
        /// <param name="ciphers"></param>
        /// <param name="isServer"></param>
        /// <returns></returns>
        /// <exception cref="InvalidOperationException"></exception>
        private static SafeSslContextHandle CreateSslContexthandle
        (
            SslStrength sslStrength,
            SslProtocol sslProtocol,
            X509Store? certificateStore,
            X509Certificate? certificate,
            PrivateKey? privateKey,
            IEnumerable<string>? ciphers,
            bool isServer = false
        )
        {
            SafeSslContextHandle sslContextHandle;

            if (Interop.Version.Library < Interop.Version.MinimumOpenSslTLS13Version
                    && (sslProtocol & SslProtocol.Tls13) == SslProtocol.Tls13)
            {
                throw new InvalidOperationException("Currently used OpenSSL library doesn't support TLS 1.3, atleast version 1.1.1 is needed.");
            }

            //initialize correct SSL method
            if (isServer)
            {
                sslContextHandle = SSLWrapper.SSL_CTX_new(SafeSslMethodHandle.DefaultServerMethod);
            }
            else
            {
                sslContextHandle = SSLWrapper.SSL_CTX_new(SafeSslMethodHandle.DefaultClientMethod);
            }

            SSLWrapper.SSL_CTX_ctrl
            (
                sslContextHandle,
                Native.SSL_CTRL_MODE,
                (int)(SslMode.SSL_MODE_ENABLE_PARTIAL_WRITE | SslMode.SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER),
                IntPtr.Zero
            );

            //set default SSL options
            Interop.SslOptions protocolOptions = Interop.SslOptions.SSL_OP_ALL;

            //disable unwanted protocols
            if ((sslProtocol & SslProtocol.Ssl3) == 0)
            {
                protocolOptions |= Interop.SslOptions.SSL_OP_NO_SSLv3;
            }

            if ((sslProtocol & SslProtocol.Tls) == 0)
            {
                protocolOptions |= Interop.SslOptions.SSL_OP_NO_TLSv1;
            }

            if ((sslProtocol & SslProtocol.Tls11) == 0)
            {
                protocolOptions |= Interop.SslOptions.SSL_OP_NO_TLSv1_1;
            }

            if ((sslProtocol & SslProtocol.Tls12) == 0)
            {
                protocolOptions |= Interop.SslOptions.SSL_OP_NO_TLSv1_2;
            } 

            if (Interop.Version.Library >= Interop.Version.MinimumOpenSslTLS13Version 
                    && (sslProtocol & SslProtocol.Tls13) == 0)
            {
                protocolOptions |= Interop.SslOptions.SSL_OP_NO_TLSv1_3;
            }

            protocolOptions |= Interop.SslOptions.SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION;

            //set the context options
            SSLWrapper.SSL_CTX_set_options(sslContextHandle, (long)protocolOptions);

            //set the security level
            SSLWrapper.SSL_CTX_set_security_level(sslContextHandle, (int)sslStrength);

            if (ciphers is not null)
            {
                string allowedCiphers = string.Join(":", ciphers);
                unsafe
                {
                    ReadOnlySpan<char> chSpan = allowedCiphers.AsSpan();
                    int count = Encoding.ASCII.GetEncoder().GetByteCount(chSpan, false);
                    //+ 1 to allow for null terminator
                    byte* b = stackalloc byte[count + 1];
                    Span<byte> bSpan = new Span<byte>(b, count + 1);
                    Encoding.ASCII.GetEncoder().GetBytes(chSpan, bSpan, true);

                    if((sslProtocol & SslProtocol.Tls13) == SslProtocol.Tls13)
                    {
                        SSLWrapper.SSL_CTX_set_ciphersuites(sslContextHandle, bSpan.GetPinnableReference());
                    }
                    else
                    {
                        SSLWrapper.SSL_CTX_set_cipher_list(sslContextHandle, bSpan.GetPinnableReference());
                    }
                }
            }

            if(certificateStore is not null)
            {
                //add an extra reference to the store, so it does not get GC'd
                CryptoWrapper.X509_STORE_up_ref(certificateStore._Handle);
                SSLWrapper.SSL_CTX_set_cert_store(sslContextHandle, certificateStore._Handle);

                if(isServer)
                {
                    //add the certificates for client certificate validation
                    using(IOpenSslReadOnlyCollection<X509Certificate> certList = certificateStore.GetCertificates())
                    {
                        foreach (X509Certificate cert in certList)
                        {
                            SSLWrapper.SSL_CTX_add_client_CA(sslContextHandle, cert._Handle);
                        }
                    }
                }

                //enable peer verifications (using the store)
                SSLWrapper.SSL_CTX_set_verify
                (
                    sslContextHandle,
                    (int)VerifyMode.SSL_VERIFY_PEER,
                    null
                );
            }

            //initialize public & private key
            //in server mode: server certificate
            //in client mode: client certificate
            if (certificate is not null
                && privateKey is not null)
            {
                if (!certificate.VerifyPrivateKey(privateKey))
                {
                    throw new InvalidOperationException("Public and private key do not match");
                }

                SSLWrapper.SSL_CTX_use_certificate(sslContextHandle, certificate._Handle);
                SSLWrapper.SSL_CTX_use_PrivateKey(sslContextHandle, privateKey._Handle);
            }

            return sslContextHandle;
        }

        internal static ISet<string> GenerateSupportedCiphers(SafeSslContextHandle sslContextHandle)
        {
            HashSet<string> supportedCiphers = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            using (SafeStackHandle<SafeSslCipherHandle> sk = Native.SSLWrapper.SSL_CTX_get_ciphers(sslContextHandle))
            {
                foreach (SafeSslCipherHandle c in sk)
                {
                    supportedCiphers.Add(Native.PtrToStringAnsi(Native.SSLWrapper.SSL_CIPHER_get_name(c), false));
                }
            }

            return supportedCiphers;
        }

        #region native callbacks
        private int SessionCallback(IntPtr sslPtr, IntPtr sessPtr)
        {
            SafeSslHandle sslhandle = Native.SafeHandleFactory.CreateWrapperSafeHandle<SafeSslHandle>(sslPtr);

            //session has already been defined, free session
            if (this._sessionHandle is not null
                || SSLWrapper.SSL_session_reused(sslhandle) == 1)
            {
                return 0;
            }

            //assign the session
            this._sessionHandle = Native.SafeHandleFactory.CreateTakeOwnershipSafeHandle<SafeSslSessionHandle>(sessPtr);

            //return 1 so that the session will not get freed again
            return 1;
        }

        //when in server mode: the client certificate
        //when in client mode: the server certificate
        private int RemoteCertificateValidationCallback(int preVerify, IntPtr x509_store_ctx_ptr)
        {
            //do not throw an exception
            if(this._remoteCertificateValidationHandler is null)
            {
                return 0;
            }

            SafeX509StoreContextHandle x509_store_ctx = Native.SafeHandleFactory.CreateWrapperSafeHandle<SafeX509StoreContextHandle>(x509_store_ctx_ptr);

            using (X509Certificate remoteCertificate = new X509Certificate(CryptoWrapper.X509_STORE_CTX_get_current_cert(x509_store_ctx)))
            {
                using (X509Store store = new X509Store(CryptoWrapper.X509_STORE_CTX_get0_store(x509_store_ctx)))
                {
                    using (IOpenSslReadOnlyCollection<X509Certificate> certList = store.GetCertificates())
                    {
                        return this._remoteCertificateValidationHandler(preVerify == 1, remoteCertificate, certList) ? 1 : 0;
                    }
                }
            }
        }

        private int ClientCertificateRequestCallback(IntPtr sslPtr, out IntPtr x509Ptr, out IntPtr pkeyPtr)
        {
            //do not throw an exception
            if(this._clientCertificateCallbackHandler is null)
            {
                x509Ptr = IntPtr.Zero;
                pkeyPtr = IntPtr.Zero;
                return 0;
            }

            SafeSslHandle ssl = Native.SafeHandleFactory.CreateWrapperSafeHandle<SafeSslHandle>(sslPtr);

            bool succes = false;
            x509Ptr = IntPtr.Zero;
            pkeyPtr = IntPtr.Zero;

            SafeStackHandle<SafeX509NameHandle> nameStackHandle = SSLWrapper.SSL_get_client_CA_list(ssl);

            using (OpenSslList<X509Name, SafeX509NameHandle> nameList = new OpenSslList<X509Name, SafeX509NameHandle>(nameStackHandle))
            {
                if (succes = this._clientCertificateCallbackHandler
                (
                    nameList,
                    out X509Certificate certificate,
                    out PrivateKey privateKey
                ))
                {
                    certificate._Handle.AddReference(); //add reference, so SSL doesn't free our objects
                    x509Ptr = certificate._Handle.DangerousGetHandle();
                    privateKey._Handle.AddReference(); //add reference, so SSL doesn't free our objects
                    pkeyPtr = privateKey._Handle.DangerousGetHandle();
                }
            }

            return succes ? 1 : 0;
        }
        #endregion

        public void Dispose()
        {
            this.Dispose(true);

            GC.SuppressFinalize(this);
        }

        public void Dispose(bool _)
        {
            try
            {
                this._sessionHandle?.Dispose();
            }
            catch
            { }
            finally
            {
                this._sessionHandle = null;
            }

            try
            {
                this._sslContextHandle.Dispose();
            }
            catch
            { }
        }
    }
}
