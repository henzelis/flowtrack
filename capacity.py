"""Capacity planning (FlowTrack 1.13.0): how full each interface is day by day and where it is heading.

The API sums the 5-minute buckets of every interface (as the input and as the output interface of the records) per
local day: the peak, the 95th percentile (empty 5 minutes count as 0, as in the Interface load panel) and the bytes.
This module turns those days into a trend and a forecast:
  * the slope is a Theil–Sen median over pairs of days a whole number of weeks apart, so the weekly rhythm (quiet
    weekends) does not pass for growth or decline and one odd day does not tilt it;
  * the level the forecast starts from is that line today plus the typical lift of the busy days above it (80th
    percentile of what is left), because a link is full on its busy days, not on average;
  * a forecast needs FORECAST_DAYS complete days with data, and it never reaches further than twice the history it
    rests on — beyond that it says "not within …" instead of a date nobody should trust.
Days on which an exporter was mostly silent (fewer than half of the 5-minute buckets have records) are left out of the
trend: an outage is no drop in demand."""
import math

FORECAST_DAYS = 14            # complete days of history before a trend is drawn
WATCH_PCT, FULL_PCT = 70, 85  # the shares the page and the reports call "worth watching" and "near full"
STABLE_PCT_MONTH = 2          # growth below ±2 % a month of the current level: "stable"


def _median(v):
    s = sorted(v)
    n = len(s)
    return 0.0 if not n else s[n // 2] if n % 2 else (s[n // 2 - 1] + s[n // 2]) / 2


def _quantile(v, q):
    s = sorted(v)
    return s[min(len(s) - 1, max(0, int(math.ceil(q * len(s))) - 1))] if s else 0.0


def trend(days):
    """days: [(day number, value)] (whole days, any gaps) -> None when there is too little history, else
    {'slope': per day, 'lo'/'hi': the quartiles of the pairwise slopes, 'level': the line on the last day,
     'busy': level + the busy days' lift, 'days': how many days, 'span': last - first + 1, 'last': the last day}."""
    days = sorted(days)
    if len(days) < FORECAST_DAYS:
        return None
    slopes = [(y2 - y1) / (x2 - x1) for i, (x1, y1) in enumerate(days) for x2, y2 in days[i + 1:] if (x2 - x1) % 7 == 0]
    if len(slopes) < 3:          # gaps left no whole weeks apart: any pair, the rhythm then shows as noise
        slopes = [(y2 - y1) / (x2 - x1) for i, (x1, y1) in enumerate(days) for x2, y2 in days[i + 1:]]
    slope = _median(slopes)
    xs = [x for x, _ in days]
    b = _median([y - slope * x for x, y in days])
    last = xs[-1]
    level = b + slope * last
    lift = _quantile([y - (b + slope * x) for x, y in days], 0.8)
    return {'slope': slope, 'lo': _quantile(slopes, 0.25), 'hi': _quantile(slopes, 0.75), 'level': max(0.0, level),
            'busy': max(0.0, level + max(0.0, lift)), 'days': len(days), 'span': last - xs[0] + 1, 'last': last,
            'median': _median([y for _, y in days])}


def forecast(tr_, cap_bps):
    """When the busy level reaches FULL_PCT and 100 % of `cap_bps` at the current slope. -> {'growth_pct_month',
    'direction' ('up' / 'down' / 'stable'), 'clear' (the quartiles of the slopes agree on the sign and are not wider than
    twice the slope: only a clear rise gets a date), 'full_in' / 'over_in' (days
    from the last day; 0 = already there, None = not within 'horizon'), 'horizon' (days), 'busy_pct'}."""
    if not tr_:
        return None
    # (1.13.1) growth against the typical day (median), not the line's end: on a link that sits near zero most days
    # the end of the line can be ~0 and the share absurd (-560 % a month on real data)
    lvl = tr_.get('median') or tr_['level'] or tr_['busy']
    g = 100 * tr_['slope'] * 30 / lvl if lvl > 0 else 0.0
    direction = 'stable' if abs(g) < STABLE_PCT_MONTH else 'up' if g > 0 else 'down'
    # clear: the quartiles of the slopes agree on the sign AND are not wider than the slope itself (noisy days)
    spread = tr_['hi'] - tr_['lo']
    clear = (tr_['lo'] > 0 if direction == 'up' else tr_['hi'] < 0 if direction == 'down' else True) and \
        (direction == 'stable' or spread <= abs(tr_['slope']) * 2)
    out = {'growth_pct_month': round(g, 1), 'direction': direction, 'clear': clear, 'horizon': 2 * tr_['span'],
           'full_in': None, 'over_in': None, 'busy_pct': None}
    if not cap_bps:
        return out
    out['busy_pct'] = round(100 * tr_['busy'] / cap_bps, 1)
    for key, pct in (('full_in', FULL_PCT), ('over_in', 100)):
        need = cap_bps * pct / 100 - tr_['busy']
        if need <= 0:
            out[key] = 0
        elif tr_['slope'] > 0 and direction == 'up' and clear:      # an unsteady trend gives no date
            d = int(math.ceil(need / tr_['slope']))
            out[key] = d if d <= out['horizon'] else None
    return out


def status(peak_pct, p95_pct, fc):
    """One word for the row and the cards: 'over' (the busy days already fill it), 'full' (near full now or within a
    month), 'soon' (near full within the forecast's reach), 'watch' (95th percentile above WATCH_PCT), 'ok', or
    'unknown' (no capacity known)."""
    if p95_pct is None:
        return 'unknown'
    if fc and fc.get('over_in') == 0 or p95_pct >= 100:
        return 'over'
    if fc and fc.get('full_in') is not None and fc['full_in'] <= 30 or p95_pct >= FULL_PCT:
        return 'full'
    if fc and fc.get('full_in') is not None:
        return 'soon'
    if p95_pct >= WATCH_PCT or (peak_pct or 0) >= FULL_PCT:
        return 'watch'
    return 'ok'


RANK = {'over': 0, 'full': 1, 'soon': 2, 'watch': 3, 'ok': 4, 'unknown': 5}
