#!/usr/bin/env python3
"""A timed-out renewal must not be treated as a released DHCP address."""
from test_feth_sessions import assess_lease_cycle,lease_cycles_pass

previous={1:'172.30.77.10',2:'172.30.77.11',3:'172.30.77.12'}
replies={1:(0,'172.30.77.10'),2:(2,''),3:(3,'')}
current={4:'172.30.77.11',5:'172.30.77.12'}
active,summary=assess_lease_cycle(previous,replies,current)
assert summary=={'renewed':1,'renew_rejected':1,'renew_not_acknowledged':1,
                 'silent_old_clients':0,'reused_unexpired_or_unconfirmed':1},summary
assert not lease_cycles_pass([summary])
assert 2 not in active and active[3]=='172.30.77.12'

# A fresh allocation cannot reuse the just-issued preflight address either.
active,summary=assess_lease_cycle({999:'172.30.77.10'},None,{1000:'172.30.77.10'})
assert summary['reused_unexpired_or_unconfirmed']==1 and len(active)==2

# Successful renewals reserve their addresses; explicit NAKs release them.
active,summary=assess_lease_cycle(previous,{1:(0,previous[1]),2:(2,''),3:(0,previous[3])},
                                  {4:'172.30.77.11',5:'172.30.77.13'})
assert summary['renew_not_acknowledged']==0 and summary['reused_unexpired_or_unconfirmed']==0
assert lease_cycles_pass([summary])
assert 2 not in active and 4 in active

# Offline clients may still use their old addresses when they reconnect.
active,summary=assess_lease_cycle(previous,{1:(0,previous[1]),2:(2,'')},
                                  {4:previous[3]},silent={3})
assert summary['silent_old_clients']==1 and summary['reused_unexpired_or_unconfirmed']==1
assert not lease_cycles_pass([summary]) and active[3]==previous[3]
_,safe=assess_lease_cycle(previous,{1:(0,previous[1]),2:(2,'')},{4:'172.30.77.13'},silent={3})
assert lease_cycles_pass([safe]) and not lease_cycles_pass([safe],crash_reused=1)
print('Lease accounting: ACK, NAK, timeout and address reuse are distinguished')
