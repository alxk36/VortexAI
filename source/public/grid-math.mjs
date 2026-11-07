// Shared projection math keeps camera rendering and pointer movement consistent.
// The world uses y as height and x/z as the horizontal movement plane.

// Wrapping bounds numerical growth without imposing either an orbit pole or a
// pitch limit. Vertical movement intentionally runs opposite to mouse delta-y.
const wrapAngle = angle => ((angle + Math.PI) % (2*Math.PI) + 2*Math.PI) % (2*Math.PI) - Math.PI;
export function orbitCamera(camera, dx, dy) {
  const yaw=Number.isFinite(camera.yaw)?camera.yaw:0;
  const pitch=Number.isFinite(camera.pitch)?camera.pitch:0;
  return {
    yaw:wrapAngle(yaw+(Number.isFinite(dx)?dx:0)*.006),
    pitch:wrapAngle(pitch-(Number.isFinite(dy)?dy:0)*.005),
  };
}

/** Screen-space marquee selection is independent of orbit orientation. Centers
 * on an edge count as selected, and dragging from any corner has equal meaning.
 */
export function nodesInRect(projectedNodes, start, end) {
  if (![start?.x,start?.y,end?.x,end?.y].every(Number.isFinite)) return [];
  const left=Math.min(start.x,end.x),right=Math.max(start.x,end.x);
  const top=Math.min(start.y,end.y),bottom=Math.max(start.y,end.y);
  return [...new Set(projectedNodes.filter(node=>
    typeof node?.id==='string' && node.id && Number.isFinite(node.x) && Number.isFinite(node.y) &&
    node.x>=left && node.x<=right && node.y>=top && node.y<=bottom
  ).map(node=>node.id))];
}

// Rotate world coordinates into camera space, then apply the same perspective
// used by screenToPlane. Depth is also returned for painter-order rendering.
export function projectPoint(point, camera) {
  const {width, height, yaw, pitch, zoom, panX = 0, panY = 0} = camera;
  const rx = point.x * Math.cos(yaw) - point.z * Math.sin(yaw);
  const rz = point.x * Math.sin(yaw) + point.z * Math.cos(yaw);
  const ry = point.y * Math.cos(pitch) - rz * Math.sin(pitch);
  const depth = point.y * Math.sin(pitch) + rz * Math.cos(pitch);
  const scale = Math.min(width / 11.8, height / 8.5) * zoom * 15 / (15 + depth);
  return {x: width * .5 + panX + rx * scale, y: height * .51 + panY - ry * scale, scale, depth};
}

/** Intersect a screen ray with y=planeY; return null at a horizon/behind camera. */
export function screenToPlane(screen, planeY, camera) {
  const {width, height, yaw, pitch, zoom, panX = 0, panY = 0} = camera;
  const focal = Math.min(width / 11.8, height / 8.5) * zoom * 15;
  if (!Number.isFinite(focal) || focal <= 0) return null;
  const u = (screen.x - width * .5 - panX) / focal;
  const v = -(screen.y - height * .51 - panY) / focal;
  const denominator = v * Math.cos(pitch) + Math.sin(pitch);
  if (Math.abs(denominator) < 1e-6) return null;
  const depth = (planeY - 15 * v * Math.cos(pitch)) / denominator;
  if (!Number.isFinite(depth) || depth <= -14.9) return null;
  const rx = u * (15 + depth), ry = v * (15 + depth);
  const rz = -ry * Math.sin(pitch) + depth * Math.cos(pitch);
  const x = rx * Math.cos(yaw) + rz * Math.sin(yaw);
  const z = -rx * Math.sin(yaw) + rz * Math.cos(yaw);
  return Number.isFinite(x) && Number.isFinite(z) ? {x, y: planeY, z} : null;
}

// Bound a group translation as a whole so relative node spacing stays intact.
export function clampTranslation(points, dx, dz, limit = 6) {
  if (!points.length || !Number.isFinite(dx) || !Number.isFinite(dz)) return {dx:0,dz:0};
  const xs = points.map(p => p.x), zs = points.map(p => p.z);
  return {
    dx: Math.max(-limit - Math.min(...xs), Math.min(limit - Math.max(...xs), dx)),
    dz: Math.max(-limit - Math.min(...zs), Math.min(limit - Math.max(...zs), dz)),
  };
}

// localStorage is untrusted input: ignore malformed, unknown and out-of-range nodes.
export function sanitizeLayout(value, nodeIds, limit = 6) {
  const clean = {};
  if (!value || typeof value !== 'object' || Array.isArray(value)) return clean;
  for (const id of nodeIds) {
    const point = Object.hasOwn(value, id) ? value[id] : null;
    if (point && Number.isFinite(point.x) && Number.isFinite(point.z) && Math.abs(point.x) <= limit && Math.abs(point.z) <= limit) {
      clean[id] = {x:point.x, z:point.z};
    }
  }
  return clean;
}
