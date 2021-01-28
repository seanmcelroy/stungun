using System;

namespace stungun.common.core
{
    public enum MessageType: ushort
    {
        BindingRequest = 0x0001,
        BindingResponse = 0x0101,
        BindingError = 0x0111
    }
}
