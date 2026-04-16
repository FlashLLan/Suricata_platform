/**
 * AnimatedPacketEdge — a custom React Flow edge that draws moving "packet" dots
 * along the edge path during simulation playback.
 *
 * How it works:
 *  - Uses getStraightPath / getBezierPath from @xyflow/react to get the SVG path string
 *  - Renders N packet circles using SVG <animateMotion> on that path
 *  - The number of dots and animation duration are driven by `packetRate` (pps)
 *    stored in edge.data
 */
import { type FC } from 'react'
import {
  getBezierPath,
  type EdgeProps,
  type Edge,
} from '@xyflow/react'

// Per-packet offset — stagger dots evenly along the path
const STAGGER_OFFSETS = [0, 0.25, 0.5, 0.75]

export interface AnimatedPacketEdgeData extends Record<string, unknown> {
  packetRate?: number   // packets per second (1–100); controls speed + dot count
  active?: boolean      // true while simulation is running
}

export type AnimatedPacketEdgeType = Edge<AnimatedPacketEdgeData>

const AnimatedPacketEdge: FC<EdgeProps<AnimatedPacketEdgeType>> = ({
  id,
  sourceX,
  sourceY,
  targetX,
  targetY,
  sourcePosition,
  targetPosition,
  data,
  style,
  markerEnd,
  selected,
}) => {
  const [edgePath] = getBezierPath({
    sourceX, sourceY, sourcePosition,
    targetX, targetY, targetPosition,
  })

  const rate     = data?.packetRate ?? 5        // default 5 pps
  const active   = data?.active ?? false

  // Duration: faster pps → shorter duration per dot
  // Clamp between 0.4s (100 pps) and 4s (1 pps)
  const durationSec = Math.max(0.4, Math.min(4, 5 / rate))

  // Dot count: 1 dot up to 4 dots based on rate
  const dotCount = rate <= 2 ? 1 : rate <= 10 ? 2 : rate <= 30 ? 3 : 4

  const dotColor = '#f87171'  // red-400 — attack packets

  return (
    <>
      {/* Base edge path */}
      <path
        id={id}
        className="react-flow__edge-path"
        d={edgePath}
        style={{
          stroke: active ? '#ef4444' : '#dc2626',
          strokeWidth: active ? 2 : 1.5,
          strokeDasharray: active ? '6 3' : undefined,
          ...style,
        }}
        markerEnd={markerEnd}
      />

      {/* Invisible wider path for easier click/hover interaction */}
      <path
        d={edgePath}
        fill="none"
        strokeWidth={20}
        stroke="transparent"
        className="react-flow__edge-interaction"
      />

      {/* Animated packet dots — only when simulation is active */}
      {active &&
        Array.from({ length: dotCount }).map((_, i) => {
          const begin = `-${(STAGGER_OFFSETS[i] * durationSec).toFixed(2)}s`
          return (
            <circle
              key={i}
              r={4}
              fill={dotColor}
              stroke="#1f2937"
              strokeWidth={1}
              opacity={0.9}
              filter="url(#packet-glow)"
            >
              <animateMotion
                dur={`${durationSec}s`}
                repeatCount="indefinite"
                begin={begin}
              >
                <mpath href={`#${id}`} />
              </animateMotion>
            </circle>
          )
        })
      }

      {/* Glow filter — defined once, referenced by all dots */}
      <defs>
        <filter id="packet-glow" x="-50%" y="-50%" width="200%" height="200%">
          <feGaussianBlur stdDeviation="2" result="blur" />
          <feMerge>
            <feMergeNode in="blur" />
            <feMergeNode in="SourceGraphic" />
          </feMerge>
        </filter>
      </defs>
    </>
  )
}

export default AnimatedPacketEdge
