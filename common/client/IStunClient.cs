using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using stungun.common.core;

namespace stungun.common.client
{
    public interface IStunClient : IDisposable
    {
        Task<MessageResponse> BindingRequestAsync(
            IList<MessageAttribute>? attributes = null,
            int connectTimeout = 5000,
            int recvTimeout = 5000,
            CancellationToken cancellationToken = default(CancellationToken),
            byte[]? customTransactionId = null);
    }
}
