use std::collections::BTreeSet;
use std::ops::Range;

use serde::Serialize;

use crate::Function;
use crate::listing::{Flow, Line, Listing};

const GAP_X: f32 = 56.0;
const GAP_Y: f32 = 72.0;
const DUMMY_WIDTH: f32 = 14.0;
const STUB: f32 = 16.0;
const STUB_STEP: f32 = 7.0;
const STUB_LANES: usize = 4;
const TOP_MARGIN: f32 = 40.0;
const ORDER_SWEEPS: usize = 8;
const POSITION_SWEEPS: usize = 8;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum EdgeKind {
    Taken,
    NotTaken,
    Always,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct Edge {
    pub to: usize,
    pub kind: EdgeKind,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Block {
    pub va: u64,
    pub lines: Range<usize>,
    pub edges: Vec<Edge>,
}

#[derive(Serialize)]
pub struct Cfg {
    #[serde(skip)]
    pub lines: Vec<Line>,
    pub blocks: Vec<Block>,
}

impl Cfg {
    pub fn build(listing: &Listing, data: &[u8], function: &Function) -> Self {
        let lines = listing.render(data, listing.rows_of(function));
        let index_of = |va: u64| lines.binary_search_by_key(&va, |line| line.va).ok();

        let mut seen = vec![false; lines.len()];
        let mut leaders = BTreeSet::new();
        let mut pending = Vec::new();
        if !lines.is_empty() {
            leaders.insert(0);
            pending.push(0);
        }

        while let Some(mut at) = pending.pop() {
            while at < lines.len() && !seen[at] {
                seen[at] = true;
                let target = lines[at].branch.and_then(index_of);
                match lines[at].flow {
                    Flow::Next => at += 1,
                    Flow::Jump => {
                        pending.extend(target);
                        leaders.extend(target);
                        break;
                    }
                    Flow::Branch => {
                        pending.extend(target);
                        leaders.extend(target);
                        at += 1;
                        leaders.insert(at);
                    }
                    Flow::Stop => break,
                }
            }
        }

        let starts: Vec<usize> = leaders
            .into_iter()
            .filter(|&at| seen.get(at) == Some(&true))
            .collect();
        let block_at = |line: usize| starts.binary_search(&line).ok();

        let blocks = starts
            .iter()
            .enumerate()
            .map(|(position, &start)| {
                let limit = starts.get(position + 1).copied().unwrap_or(lines.len());
                let last = (start..limit)
                    .find(|&at| !matches!(lines[at].flow, Flow::Next))
                    .unwrap_or(limit - 1);
                let fallthrough = block_at(last + 1);
                let target = lines[last].branch.and_then(index_of).and_then(block_at);

                let edge = |to, kind| Edge { to, kind };
                let edges = match lines[last].flow {
                    Flow::Next => fallthrough
                        .map(|to| edge(to, EdgeKind::Always))
                        .into_iter()
                        .collect(),
                    Flow::Jump => target
                        .map(|to| edge(to, EdgeKind::Always))
                        .into_iter()
                        .collect(),
                    Flow::Branch => target
                        .map(|to| edge(to, EdgeKind::Taken))
                        .into_iter()
                        .chain(fallthrough.map(|to| edge(to, EdgeKind::NotTaken)))
                        .collect(),
                    Flow::Stop => Vec::new(),
                };

                Block {
                    va: lines[start].va,
                    lines: start..last + 1,
                    edges,
                }
            })
            .collect();

        Self { lines, blocks }
    }

    pub fn block_of_line(&self, line: usize) -> Option<usize> {
        self.blocks
            .iter()
            .position(|block| block.lines.contains(&line))
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct Placement {
    pub x: f32,
    pub y: f32,
    pub width: f32,
    pub height: f32,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Route {
    pub from: usize,
    pub to: usize,
    pub back: bool,
    pub points: Vec<(f32, f32)>,
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct GraphLayout {
    pub nodes: Vec<Placement>,
    pub routes: Vec<Route>,
    pub width: f32,
    pub height: f32,
}

struct Layering {
    ranks: Vec<Vec<usize>>,
    above: Vec<Vec<usize>>,
    below: Vec<Vec<usize>>,
    widths: Vec<f32>,
    chains: Vec<Vec<usize>>,
    back: Vec<bool>,
}

pub fn layout(sizes: &[(f32, f32)], edges: &[(usize, usize)]) -> GraphLayout {
    if sizes.is_empty() {
        return GraphLayout::default();
    }

    let mut layering = build_layers(sizes, edges);
    order_ranks(&mut layering);
    let centers = position_ranks(&layering);
    place(sizes, edges, &layering, &centers)
}

fn find_back_edges(count: usize, edges: &[(usize, usize)]) -> Vec<bool> {
    let mut outgoing = vec![Vec::new(); count];
    for (index, &(from, _)) in edges.iter().enumerate() {
        outgoing[from].push(index);
    }

    let mut back = vec![false; edges.len()];
    let mut state = vec![0u8; count];
    for root in 0..count {
        if state[root] != 0 {
            continue;
        }

        let mut stack = vec![(root, 0)];
        state[root] = 1;
        while let Some(&mut (node, ref mut next)) = stack.last_mut() {
            match outgoing[node].get(*next) {
                Some(&edge) => {
                    *next += 1;
                    let to = edges[edge].1;
                    match state[to] {
                        0 => {
                            state[to] = 1;
                            stack.push((to, 0));
                        }
                        1 => back[edge] = true,
                        _ => {}
                    }
                }
                None => {
                    state[node] = 2;
                    stack.pop();
                }
            }
        }
    }
    back
}

fn assign_layers(count: usize, edges: &[(usize, usize)], back: &[bool]) -> Vec<usize> {
    let mut outgoing = vec![Vec::new(); count];
    let mut incoming = vec![0; count];
    for (index, &(from, to)) in edges.iter().enumerate() {
        if !back[index] {
            outgoing[from].push(to);
            incoming[to] += 1;
        }
    }

    let mut layers = vec![0; count];
    let mut ready: Vec<usize> = (0..count).filter(|&node| incoming[node] == 0).collect();
    while let Some(node) = ready.pop() {
        for &to in &outgoing[node] {
            layers[to] = layers[to].max(layers[node] + 1);
            incoming[to] -= 1;
            if incoming[to] == 0 {
                ready.push(to);
            }
        }
    }
    layers
}

fn build_layers(sizes: &[(f32, f32)], edges: &[(usize, usize)]) -> Layering {
    let back = find_back_edges(sizes.len(), edges);
    let layers = assign_layers(sizes.len(), edges, &back);
    let rank_count = layers.iter().max().map_or(1, |top| top + 1);

    let mut ranks = vec![Vec::new(); rank_count];
    for (node, &layer) in layers.iter().enumerate() {
        ranks[layer].push(node);
    }

    let mut widths: Vec<f32> = sizes.iter().map(|size| size.0).collect();
    let mut chains = Vec::with_capacity(edges.len());
    for (index, &(from, to)) in edges.iter().enumerate() {
        let (top, bottom) = if layers[from] <= layers[to] {
            (from, to)
        } else {
            (to, from)
        };
        // Back edges also reserve a lane in both end ranks, so they can go around those blocks.
        let lanes = if back[index] {
            layers[top]..layers[bottom] + 1
        } else {
            (layers[top] + 1).min(layers[bottom])..layers[bottom]
        };
        let mut chain = vec![top];
        for rank in &mut ranks[lanes] {
            rank.push(widths.len());
            chain.push(widths.len());
            widths.push(DUMMY_WIDTH);
        }
        chain.push(bottom);
        chains.push(chain);
    }

    let mut above = vec![Vec::new(); widths.len()];
    let mut below = vec![Vec::new(); widths.len()];
    for chain in &chains {
        for pair in chain.windows(2) {
            if pair[0] != pair[1] {
                below[pair[0]].push(pair[1]);
                above[pair[1]].push(pair[0]);
            }
        }
    }

    Layering {
        ranks,
        above,
        below,
        widths,
        chains,
        back,
    }
}

fn average(neighbors: &[usize], values: &[f32]) -> Option<f32> {
    if neighbors.is_empty() {
        return None;
    }
    let sum: f32 = neighbors.iter().map(|&node| values[node]).sum();
    Some(sum / neighbors.len() as f32)
}

fn order_ranks(layering: &mut Layering) {
    let mut order = vec![0.0; layering.widths.len()];
    let record = |ranks: &[Vec<usize>], order: &mut [f32]| {
        for rank in ranks {
            for (position, &node) in rank.iter().enumerate() {
                order[node] = position as f32;
            }
        }
    };
    record(&layering.ranks, &mut order);

    for sweep in 0..ORDER_SWEEPS {
        let downward = sweep % 2 == 0;
        let count = layering.ranks.len();
        for step in 0..count {
            let rank = if downward { step } else { count - 1 - step };
            let neighbors = if downward {
                &layering.above
            } else {
                &layering.below
            };
            let keys: Vec<(f32, usize)> = layering.ranks[rank]
                .iter()
                .map(|&node| {
                    (
                        average(&neighbors[node], &order).unwrap_or(order[node]),
                        node,
                    )
                })
                .collect();

            let mut sorted = keys;
            sorted.sort_by(|a, b| a.0.total_cmp(&b.0));
            layering.ranks[rank] = sorted.iter().map(|&(_, node)| node).collect();
            for (position, &node) in layering.ranks[rank].iter().enumerate() {
                order[node] = position as f32;
            }
        }
    }
}

fn position_ranks(layering: &Layering) -> Vec<f32> {
    let widths = &layering.widths;
    let mut centers = vec![0.0; widths.len()];
    for rank in &layering.ranks {
        let mut x = 0.0;
        for &node in rank {
            centers[node] = x + widths[node] / 2.0;
            x += widths[node] + GAP_X;
        }
    }

    for sweep in 0..POSITION_SWEEPS {
        let downward = sweep % 2 == 0;
        let count = layering.ranks.len();
        for step in 0..count {
            let rank = &layering.ranks[if downward { step } else { count - 1 - step }];
            let neighbors = if downward {
                &layering.above
            } else {
                &layering.below
            };
            let desired: Vec<f32> = rank
                .iter()
                .map(|&node| average(&neighbors[node], &centers).unwrap_or(centers[node]))
                .collect();

            let spacing = |left: usize, right: usize| {
                (widths[rank[left]] + widths[rank[right]]) / 2.0 + GAP_X
            };
            let mut pushed_right = desired.clone();
            for i in 1..rank.len() {
                pushed_right[i] = pushed_right[i].max(pushed_right[i - 1] + spacing(i - 1, i));
            }
            let mut pushed_left = desired;
            for i in (1..rank.len()).rev() {
                pushed_left[i - 1] = pushed_left[i - 1].min(pushed_left[i] - spacing(i - 1, i));
            }
            for (i, &node) in rank.iter().enumerate() {
                centers[node] = (pushed_right[i] + pushed_left[i]) / 2.0;
            }
        }
    }
    centers
}

fn port(index: usize, count: usize, width: f32) -> f32 {
    let share = (index + 1) as f32 / (count + 1) as f32 - 0.5;
    share * width * 0.7
}

fn place(
    sizes: &[(f32, f32)],
    edges: &[(usize, usize)],
    layering: &Layering,
    centers: &[f32],
) -> GraphLayout {
    let left = layering
        .ranks
        .iter()
        .flatten()
        .map(|&node| centers[node] - layering.widths[node] / 2.0)
        .fold(f32::INFINITY, f32::min);

    let mut rank_top = Vec::with_capacity(layering.ranks.len());
    let mut rank_height = Vec::with_capacity(layering.ranks.len());
    let mut rank_of = vec![0; layering.widths.len()];
    let mut y = TOP_MARGIN;
    for (index, rank) in layering.ranks.iter().enumerate() {
        let height = rank
            .iter()
            .filter(|&&node| node < sizes.len())
            .map(|&node| sizes[node].1)
            .fold(0.0, f32::max);
        for &node in rank {
            rank_of[node] = index;
        }
        rank_top.push(y);
        rank_height.push(height);
        y += height + GAP_Y;
    }

    let center = |node: usize| centers[node] - left;
    let nodes: Vec<Placement> = sizes
        .iter()
        .enumerate()
        .map(|(node, &(width, height))| Placement {
            x: center(node) - width / 2.0,
            y: rank_top[rank_of[node]],
            width,
            height,
        })
        .collect();

    let ports_for = |select: fn(&(usize, usize)) -> usize, sort: fn(&(usize, usize)) -> usize| {
        let mut ports = vec![0.0; edges.len()];
        for (node, size) in sizes.iter().enumerate() {
            let mut group: Vec<usize> = (0..edges.len())
                .filter(|&edge| select(&edges[edge]) == node)
                .collect();
            group.sort_by(|&a, &b| center(sort(&edges[a])).total_cmp(&center(sort(&edges[b]))));
            for (position, &edge) in group.iter().enumerate() {
                ports[edge] = port(position, group.len(), size.0);
            }
        }
        ports
    };
    let exits = ports_for(|edge| edge.0, |edge| edge.1);
    let entries = ports_for(|edge| edge.1, |edge| edge.0);

    let routes = edges
        .iter()
        .enumerate()
        .map(|(index, &(from, to))| {
            let chain = &layering.chains[index];
            let between = &chain[1..chain.len() - 1];
            let back = layering.back[index];

            let start = (
                center(from) + exits[index],
                nodes[from].y + nodes[from].height,
            );
            let end = (center(to) + entries[index], nodes[to].y);

            let mut points = vec![start];
            if back {
                let stub = STUB + (index % STUB_LANES) as f32 * STUB_STEP;
                let rank_bottom = rank_top[rank_of[from]] + rank_height[rank_of[from]];
                let below = rank_bottom + stub;
                let above = end.1 - stub;

                points.push((start.0, below));
                if let Some(&first) = between.last() {
                    points.push((center(first), below));
                }
                for &dummy in between.iter().rev() {
                    let rank = rank_of[dummy];
                    points.push((center(dummy), rank_top[rank] + rank_height[rank]));
                    points.push((center(dummy), rank_top[rank]));
                }
                if let Some(&last) = between.first() {
                    points.push((center(last), above));
                }
                points.push((end.0, above));
            } else {
                for &dummy in between {
                    let rank = rank_of[dummy];
                    points.push((center(dummy), rank_top[rank]));
                    points.push((center(dummy), rank_top[rank] + rank_height[rank]));
                }
            }
            points.push(end);

            Route {
                from,
                to,
                back,
                points,
            }
        })
        .collect();

    let width = layering
        .ranks
        .iter()
        .flatten()
        .map(|&node| center(node) + layering.widths[node] / 2.0)
        .fold(0.0, f32::max);
    let height = nodes
        .iter()
        .map(|node| node.y + node.height)
        .fold(0.0, f32::max)
        + TOP_MARGIN;
    GraphLayout {
        nodes,
        routes,
        width,
        height,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Arch, Section};

    const SIZE: (f32, f32) = (100.0, 40.0);

    fn analyze(code: &[u8]) -> Cfg {
        let section = Section {
            va: 0x1000,
            offset: 0,
            size: code.len() as u64,
            executable: true,
        };
        let function = Function {
            va: 0x1000,
            size: code.len() as u64,
            name: None,
        };
        let listing = Listing::build(
            code,
            Arch::X86_64,
            &[section],
            std::slice::from_ref(&function),
        );
        Cfg::build(&listing, code, &function)
    }

    #[test]
    fn splits_a_branch_into_three_blocks() {
        // je +1; nop; ret, where both paths meet at the ret
        let cfg = analyze(&[0x74, 0x01, 0x90, 0xC3]);

        assert_eq!(cfg.blocks.len(), 3);
        assert_eq!(cfg.blocks[0].va, 0x1000);
        assert_eq!(
            cfg.blocks[0].edges,
            [
                Edge {
                    to: 2,
                    kind: EdgeKind::Taken
                },
                Edge {
                    to: 1,
                    kind: EdgeKind::NotTaken
                },
            ]
        );
        assert_eq!(
            cfg.blocks[1].edges,
            [Edge {
                to: 2,
                kind: EdgeKind::Always
            }]
        );
        assert!(cfg.blocks[2].edges.is_empty());
    }

    #[test]
    fn finds_a_loop_and_ignores_unreachable_padding() {
        // nop; jmp back to nop, then int3 padding that nothing reaches
        let cfg = analyze(&[0x90, 0xEB, 0xFD, 0xCC, 0xCC]);

        assert_eq!(cfg.blocks.len(), 1);
        assert_eq!(
            cfg.blocks[0].edges,
            [Edge {
                to: 0,
                kind: EdgeKind::Always
            }]
        );
        assert_eq!(cfg.blocks[0].lines, 0..2);
    }

    #[test]
    fn lays_out_layers_top_down_without_overlap() {
        let edges = [(0, 1), (0, 2), (1, 3), (2, 3), (0, 3)];
        let graph = layout(&[SIZE; 4], &edges);

        assert!(graph.nodes[0].y < graph.nodes[1].y);
        assert_eq!(graph.nodes[1].y, graph.nodes[2].y);
        assert!(graph.nodes[2].y < graph.nodes[3].y);

        let (a, b) = (graph.nodes[1], graph.nodes[2]);
        assert!(a.x + a.width <= b.x || b.x + b.width <= a.x);
        assert!(graph.nodes.iter().all(|node| node.x >= 0.0));
    }

    #[test]
    fn routes_long_edges_around_the_middle_layer() {
        let edges = [(0, 1), (1, 2), (0, 2)];
        let graph = layout(&[SIZE; 3], &edges);

        let long = &graph.routes[2];
        assert!(long.points.len() > 2);

        let middle = graph.nodes[1];
        let (x, _) = long.points[1];
        assert!(x <= middle.x || x >= middle.x + middle.width);
    }

    #[test]
    fn lays_out_disconnected_groups_and_cycles_away_from_the_first_node() {
        let edges = [(1, 2), (2, 3), (3, 1)];
        let graph = layout(&[SIZE; 5], &edges);

        assert_eq!(graph.routes.iter().filter(|route| route.back).count(), 1);
        for (index, a) in graph.nodes.iter().enumerate() {
            for b in &graph.nodes[index + 1..] {
                let apart = a.x + a.width <= b.x || b.x + b.width <= a.x || a.y != b.y;
                assert!(apart);
            }
        }
    }

    #[test]
    fn every_arrow_leaves_a_bottom_edge_and_enters_a_top_edge() {
        let edges = [(0, 1), (1, 2), (2, 1), (2, 0), (1, 1), (0, 2)];
        let graph = layout(&[SIZE; 3], &edges);

        for route in &graph.routes {
            let from = graph.nodes[route.from];
            let to = graph.nodes[route.to];
            let (first, last) = (route.points[0], route.points[route.points.len() - 1]);

            assert_eq!(first.1, from.y + from.height);
            assert!(first.0 >= from.x && first.0 <= from.x + from.width);
            assert_eq!(last.1, to.y);
            assert!(last.0 >= to.x && last.0 <= to.x + to.width);

            let before = route.points[route.points.len() - 2];
            assert!(before.1 < last.1);
            if route.back {
                assert_eq!(before.0, last.0);
            }
            assert!(route.points.iter().all(|point| point.1 >= 0.0));
        }
    }

    #[test]
    fn back_edges_travel_in_lanes_clear_of_every_block() {
        let edges = [(0, 1), (1, 2), (2, 0)];
        let graph = layout(&[SIZE; 3], &edges);

        let back = graph.routes.iter().find(|route| route.back).unwrap();
        let lane: Vec<_> = back.points[2..back.points.len() - 2].to_vec();
        assert!(!lane.is_empty());
        for point in lane {
            for node in &graph.nodes {
                let inside_x = point.0 > node.x && point.0 < node.x + node.width;
                let inside_y = point.1 > node.y && point.1 < node.y + node.height;
                assert!(!(inside_x && inside_y), "{point:?} is inside {node:?}");
            }
        }
    }

    #[test]
    fn marks_back_edges_and_self_loops() {
        let edges = [(0, 1), (1, 0), (1, 1)];
        let graph = layout(&[SIZE; 2], &edges);

        assert!(!graph.routes[0].back);
        assert!(graph.routes[1].back);
        assert!(graph.routes[2].back);
        assert!(graph.nodes[0].y < graph.nodes[1].y);
    }
}
