enum PACKET_TYPES // for which we wish to detect intrusions for
{
    DEAUTH, // requires sender_mac, receiver_mac and channel id
    PROBE_REQ, // requires sender_mac, (generally broadcast but still)receiver_mac and channel id
    BEACON, // requires sender_mac and channel id
    OTHER // ignore
};

struct config
{
    // for each packet type, maintain a threshold value and rolling time window size like int deauth_threshold, deauth_time_window, ....

    // then, a STATS_CALCULATION_INTERVAL to periodically calculate stats and check for intrusions
}
struct map_element
{
    mac_address sender_mac;
    map<PACKET_TYPES,set<timestamp>> packet_type_to_timestamps; // for each packet type, maintain a set of timestamps when packets were seen from this sender_mac 
}
class IDS
{
    private:
    config my_config; // const variables for config

    // data structures to maintain rolling counts for each sender_mac and packet type
    // current design - a map from sender_mac to all the packet types and their timestamps seen from this sender_mac
    // periodically, stats will be calculated from this data structure to check for intrusions
    map<sender_mac, map_element> sender_mac_to_map_element;
    

    public:
    extract_n_categorize(packet)
    {
        switch(packet.type)
        {
            case DEAUTH:
                process_deauth(packet);
                break;
            case PROBE_REQ:
                process_deauth(packet);
                break;
            case BEACON:
                process_deauth(packet);
                break;
            default:
                increment_total_packet_count(packet); // for the sender
                // ignore
                break;
        }
    }

    // now each individual process_xxx will maintain a rolling window of counts for each sender_mac
    // example implementation
    process_deauth(packet)
    {
        // extract sender_mac, receiver_mac, channel id from packet
        // necessary updations in the sender_mac_to_map_element data structure
    }

    periodically_calculate_stats_and_check_for_intrusions()
    {
        // for each sender_mac in sender_mac_to_map_element
        //      for each packet type
        //          calculate count of packets in the rolling time window
        //          compare with threshold from config
        //          if threshold crossed, raise intrusion alert
    }

    int main()
    {
        time next_stats_calculation = current_time + STATS_CALCULATION_INTERVAL;
        while(true)
        {
            packet = capture_next_packet();
            extract_n_categorize(packet);
            if(current_time >= next_stats_calculation)
            {
                periodically_calculate_stats_and_check_for_intrusions();
                next_stats_calculation += STATS_CALCULATION_INTERVAL;
            }
        }
        return 0;
    }
}