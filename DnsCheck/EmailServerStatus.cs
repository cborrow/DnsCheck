using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace DnsCheck
{
    public class EmailServerStatus
    {
        bool online;
        public bool Online
        {
            get { return online; }
            set { online = value; }
        }

        bool open;
        public bool Open
        {
            get { return open; }
            set { open = value; }
        }

        bool allowsRelay;
        public bool AllowsRelay
        {
            get { return allowsRelay; }
            set { allowsRelay = value; }
        }
    }
}
