using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
using stungun.common.core;

namespace stungun.client.core
{
    public interface IStunClient : IDisposable
    {
        Task<MessageResponse> BindingRequestAsync(int connectTimeout = 5000, int recvTimeout = 5000, CancellationToken cancellationToken = default(CancellationToken));
    }
}
