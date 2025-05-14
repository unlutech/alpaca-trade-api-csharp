using System;
using System.Collections.Generic;
using System.Text;

namespace Alpaca.Markets.Authentication
{
    /// <summary>
    /// Secret API key for Alpaca API authentication.
    /// </summary>
    public sealed class PiapiriKey : SecurityKey
    {
        /// <summary>
        /// Creates a new instance of <see cref="PiapiriKey"/> object.
        /// </summary>
        /// <param name="keyId">Secret API key identifier.</param>
        /// <param name="value">Secret API key value.</param>
        /// <exception cref="ArgumentNullException">
        /// The <paramref name="keyId"/> or <paramref name="value"/> argument is <c>null</c>.
        /// </exception>
        public PiapiriKey(
            String keyId,
            String value)
            : base(value) =>
            KeyId = keyId.EnsureNotNull();

        private String KeyId { get; }

        internal override IEnumerable<KeyValuePair<String, String>> GetAuthenticationHeaders()
        {
            yield return new KeyValuePair<String, String>(
                                "Authorization", "Basic " + Convert.ToBase64String(Encoding.ASCII.GetBytes(
                    $"{KeyId}:{Value}")));
        }

        internal override JsonAuthRequest.JsonData GetAuthenticationData() =>
            new()
            {
                KeyId = KeyId,
                SecretKey = Value
            };

        internal override JsonAuthentication GetAuthentication() =>
            new()
            {
                Action = JsonAction.StreamingAuthenticate,
                SecretKey = Value,
                KeyId = KeyId
            };
    }
}
