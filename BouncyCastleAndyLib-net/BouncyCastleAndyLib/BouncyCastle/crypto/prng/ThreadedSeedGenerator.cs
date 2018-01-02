using System;
using System.Threading;

namespace Org.BouncyCastle.Crypto.Prng
{
	/**
	 * A thread based seed generator - one source of randomness.
	 * <p>
	 * Based on an idea from Marcus Lippert.
	 * </p>
	 */
	public class ThreadedSeedGenerator
	{
		private class SeedGenerator
		{
			private volatile int	counter = 0;
			private volatile bool	stop = false;

			private void Run()
			{
				while (!this.stop)
				{
					this.counter++;
				}

			}

			public byte[] GenerateSeed(
				int		numBytes,
				bool	fast)
			{
				this.counter = 0;
				this.stop = false;

				byte[] result = new byte[numBytes];
				int last = 0;
				int end = fast ? numBytes : numBytes * 8;

				Thread t = new Thread(new ThreadStart(Run));
				t.Start();

				for (int i = 0; i < end; i++)
				{
					while (this.counter == last)
					{
						try
						{
							Thread.Sleep(1);
						}
						catch (ThreadInterruptedException)
						{
							// ignore
						}
					}

					last = this.counter;

					if (fast)
					{
						result[i] = (byte) last;
					}
					else
					{
						int bytepos = i / 8;
						result[bytepos] = (byte) ((result[bytepos] << 1) | (last & 1));
					}
				}

				this.stop = true;
				t.Join();

				return result;
			}
		}

		/**
		 * Generate seed bytes. Set fast to false for best quality.
		 * <p>
		 * If fast is set to true, the code should be round about 8 times faster when
		 * generating a long sequence of random bytes. 20 bytes of random values using
		 * the fast mode take less than half a second on a Nokia e70. If fast is set to false,
		 * it takes round about 2500 ms.
		 * </p>
		 * @param numBytes the number of bytes to generate
		 * @param fast true if fast mode should be used
		 */
		public byte[] GenerateSeed(
			int		numBytes,
			bool	fast)
		{
			return new SeedGenerator().GenerateSeed(numBytes, fast);
		}
	}
}
