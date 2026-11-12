"""Draw one chart (benchmark.png) and a Markdown table (benchmark_table.md) from benchmark.csv.

Usage: python3 plot_results.py [path/to/benchmark.csv]      (default: results/benchmark.csv)
The two output files are written next to the CSV. Uses matplotlib, with no display needed.
"""
import csv
import os
import statistics
import sys

import matplotlib
matplotlib.use('Agg')          # draw into a file, not a window
import matplotlib.pyplot as plt

ROOT = os.path.dirname(os.path.abspath(__file__))
CSV_PATH = sys.argv[1] if len(sys.argv) > 1 else os.path.join(ROOT, 'results', 'benchmark.csv')
OUT_DIR = os.path.dirname(os.path.abspath(CSV_PATH))
MODES = [('plain', 'Plain learning switch', '#4c78a8'), ('controlled', 'With access control', '#f58518')]
SCENARIOS = [(1, '1 client'), (2, '2 clients at once')]
# (csv column, panel title, y label, divide values by)
PANELS = [('login_ms', 'Login time (access control only)', 'milliseconds', 1),
          ('first_ping_ms', 'Time until the first ping gets through', 'milliseconds', 1),
          ('avg_ping_ms', 'Average ping round trip', 'milliseconds', 1),
          ('iperf_mbps', 'TCP throughput per client', 'Gbit/s', 1000)]


def load(path):
    with open(path, newline='') as f:
        return list(csv.DictReader(f))


def mean(rows, mode, clients, column):
    """Median of a column over every client and every repeat of one scenario; None if there is no value.
    (The median, so one unusually slow or fast run does not decide the bar. The name is kept short.)"""
    values = [float(r[column]) for r in rows if r['mode'] == mode and int(r['clients']) == clients and r[column] != '']
    return statistics.median(values) if values else None


def runs(rows):
    """How many repeats the CSV holds."""
    return len({r['run'] for r in rows})


def draw(rows, path):
    fig, axes = plt.subplots(2, 2, figsize=(11, 7.5))
    for ax, (column, title, ylabel, divide) in zip(axes.flat, PANELS):
        width = 0.36
        shown = [m for m, (mode, _, _) in enumerate(MODES) if any(mean(rows, mode, c, column) is not None for c, _ in SCENARIOS)]
        for m, (mode, label, color) in enumerate(MODES):
            xs, heights = [], []
            # two bars side by side; a panel with only one setup (login time) centres its bars
            offset = 0 if len(shown) == 1 else (m - 0.5) * width
            for i, (clients, _) in enumerate(SCENARIOS):
                value = mean(rows, mode, clients, column)
                if value is not None:
                    xs.append(i + offset)
                    heights.append(value / divide)
            bars = ax.bar(xs, heights, width, color=color, label=label)
            for bar, h in zip(bars, heights):
                text = '%.1f' % h if h >= 10 else '%.2f' % h if h >= 1 else '%.3f' % h
                ax.text(bar.get_x() + bar.get_width() / 2, h, text, ha='center', va='bottom', fontsize=9)
        ax.set_xticks(range(len(SCENARIOS)))
        ax.set_xticklabels([name for _, name in SCENARIOS])
        ax.set_title(title, fontsize=11)
        ax.set_ylabel(ylabel)
        ax.margins(y=0.15)
        ax.spines[['top', 'right']].set_visible(False)
        ax.grid(axis='y', alpha=0.3)
        if column == 'login_ms':
            ax.text(0.5, 0.92, 'a plain switch has no login', transform=ax.transAxes, ha='center', fontsize=9, color='#555555')
    handles, labels = axes.flat[1].get_legend_handles_labels()
    fig.legend(handles, labels, loc='lower center', ncol=2, frameon=False)
    fig.suptitle('Plain learning switch vs access-controlled network (h4, h5 -> h3), median of %d runs' % runs(rows), fontsize=13)
    fig.tight_layout(rect=(0, 0.05, 1, 0.96))
    fig.savefig(path, dpi=150)
    plt.close(fig)


def table(rows):
    """Markdown table: one line per (mode, clients), the median over all clients and repeats."""
    def show(v, digits):
        return '-' if v is None else '%.*f' % (digits, v)
    lines = ['| Setup | Clients | Reached h3 before login | Login (ms) | First ping (ms) | Avg ping (ms) | Throughput per client (Mbit/s) |',
             '|---|---|---|---|---|---|---|']
    for mode, label, _ in MODES:
        for clients, _ in SCENARIOS:
            mine = [r for r in rows if r['mode'] == mode and int(r['clients']) == clients]
            if not mine:
                continue
            yes = sum(r['reach_before_login'] == 'yes' for r in mine)
            lines.append('| %s | %d | %s | %s | %s | %s | %s |' % (
                label, clients, '%d of %d' % (yes, len(mine)), show(mean(rows, mode, clients, 'login_ms'), 1),
                show(mean(rows, mode, clients, 'first_ping_ms'), 1), show(mean(rows, mode, clients, 'avg_ping_ms'), 3),
                show(mean(rows, mode, clients, 'iperf_mbps'), 0)))
    return '\n'.join(lines) + '\n'


if __name__ == '__main__':
    data = load(CSV_PATH)
    draw(data, os.path.join(OUT_DIR, 'benchmark.png'))
    with open(os.path.join(OUT_DIR, 'benchmark_table.md'), 'w') as f:
        f.write(table(data))
    print('wrote', os.path.join(OUT_DIR, 'benchmark.png'), 'and benchmark_table.md')
