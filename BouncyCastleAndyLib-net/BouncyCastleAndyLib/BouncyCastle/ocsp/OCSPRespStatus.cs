using System;

namespace Org.BouncyCastle.Ocsp
{
	public abstract class OcscpRespStatus
	{
		/**
		 * note 4 is not used.
		 */
		public static readonly int Successful = 0;			// --Response has valid confirmations
		public static readonly int MalformedRequest = 1;	// --Illegal confirmation request
		public static readonly int InternalError = 2;		// --Internal error in issuer
		public static readonly int TryLater = 3;			// --Try again later
		public static readonly int SigRequired = 5;			// --Must sign the request
		public static readonly int Unauthorized = 6;		//  --Request unauthorized
	}
}
