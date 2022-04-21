global AgentsOfIP : table[addr] of set[string];

event http_header(c: connection)
{
    local source = c$id$orig_h;
    local dest = to_lower(c$http$user_agent);
    if (source !in AgentsOfIP)
    {
        AgentsOfIP[source] = set();
        add AgentsOfIP[source][dest];
    }
    else
    {
        if (dest !in AgentsOfIP[source])
        {
            add AgentsOfIP[source][dest];
        }
    }
}

event zeek_done()
{
    for (x in AgentsOfIP)
    {
        if (| AgentsOfIP[x] | >= 3)
        {
            print fmt("%s is a proxy", x);
        }
    }
}
