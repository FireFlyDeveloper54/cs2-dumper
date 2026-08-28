//! The world-to-screen matrix, found by the geometry only a projection matrix
//! has.
//!
//! `dwViewMatrix` is one of the offsets consumers reach for most, and the
//! signature that finds it describes the code that writes the matrix. The matrix
//! itself is far more distinctive than that code: it is sixteen floats in
//! `client.dll`'s writable data, and the four that form its `w` row are the view
//! forward axis, so they are a *unit vector* — while the rows that produce screen
//! x and y are scaled copies of the camera's right and up axes, and are therefore
//! perpendicular to it.
//!
//! That is a description of a world-to-clip matrix rather than of CS2, so it
//! holds for any Source 2 title and any build. It also excludes the thing a
//! module's data is otherwise full of: an affine transform's last row is
//! `(0, 0, 0, 1)`, whose direction part has no length at all, so bone and
//! entity-transform matrices cannot pass.
//!
//! The scan works inside the live image copy the caller already read — no
//! process reads of its own — and reports a matrix only when exactly one block
//! in the module fits. A second matrix that fits is either a copy the engine
//! updates or one it wrote once and abandoned, and from here those look alike; a
//! stale matrix draws a coherent, wrong world, so the symbol is left missing
//! instead.

/// Candidate blocks collected before the scan stops. It only has to answer "is
/// there exactly one?", so two is already the whole answer.
const MAX_CANDIDATES: usize = 4;

/// How far a dot product may stray from zero, relative to the row's own length,
/// for two axes to count as perpendicular. The matrix is built from floats and
/// from angles the engine rounded, so exact orthogonality is not on offer.
const SQUARE_TOLERANCE: f32 = 0.02;

/// Length the `w` row must have. It is a rotation axis, so it is one — the slack
/// absorbs float error and any small scale the engine folds into the row.
const UNIT: (f32, f32) = (0.98, 1.02);

/// VA of the view matrix in `image`, a live copy of the module at `base`, or
/// `None` when no single 16-float block in `ranges` has a projection matrix's
/// geometry.
pub fn find_in_image(image: &[u8], base: u64, ranges: &[(u64, u64)]) -> Option<u64> {
    let mut found: Vec<u64> = Vec::new();

    for &(rva, size) in ranges {
        let start = (rva as usize).min(image.len());
        let end = start.saturating_add(size as usize).min(image.len());
        let mut offset = start.next_multiple_of(4);

        while offset
            .checked_add(64)
            .is_some_and(|candidate_end| candidate_end <= end)
            && found.len() < MAX_CANDIDATES
        {
            let block = &image[offset..offset + 64];
            if let Some(matrix) = floats(block)
                && is_projection(&matrix)
            {
                let Some(va) = base.checked_add(offset as u64) else {
                    offset += 4;
                    continue;
                };
                found.push(va);
                // A shifted window over the same matrix is a different matrix,
                // but never a plausible one, so the scan does not skip ahead.
            }
            offset += 4;
        }
    }

    match found.as_slice() {
        [only] => Some(*only),
        _ => None,
    }
}

/// Sixteen finite floats of plausible magnitude, or `None` for a block that is
/// not float data at all. Rejecting `NaN` here is what keeps every comparison
/// below meaningful.
fn floats(block: &[u8]) -> Option<[f32; 16]> {
    let mut matrix = [0f32; 16];
    for (slot, bytes) in matrix.iter_mut().zip(block.as_chunks::<4>().0) {
        let value = f32::from_le_bytes(*bytes);
        if !value.is_finite() || value.abs() > 1.0e6 {
            return None;
        }
        *slot = value;
    }
    Some(matrix)
}

/// Whether `matrix` has the geometry of a world-to-clip matrix, read either
/// row-major or column-major.
///
/// Both conventions are checked because the layout is the engine's business and
/// the answer — the address — is the same either way. Checking both cannot
/// create an ambiguity: it is one block of memory, and one candidate.
fn is_projection(matrix: &[f32; 16]) -> bool {
    is_row_major_projection(matrix) || is_row_major_projection(&transposed(matrix))
}

fn is_row_major_projection(m: &[f32; 16]) -> bool {
    let row = |index: usize| [m[index * 4], m[index * 4 + 1], m[index * 4 + 2]];
    let (screen_x, screen_y, depth, w) = (row(0), row(1), row(2), row(3));

    // The `w` row is the view forward axis: a unit vector. An affine transform's
    // last row is `(0, 0, 0, 1)` and fails here, which is what keeps the scan
    // off the transform matrices a module's data is full of.
    if !(UNIT.0..=UNIT.1).contains(&length(w)) {
        return false;
    }
    // Screen x and y come from the right and up axes, scaled by the projection.
    // Both are perpendicular to forward, and neither is degenerate.
    if !scaled_axis(screen_x, w) || !scaled_axis(screen_y, w) {
        return false;
    }
    // The depth row is the forward axis again, scaled: parallel, not
    // perpendicular. Some projections leave it tiny, so only its direction is
    // asserted.
    let depth_length = length(depth);
    depth_length > 1.0e-6
        && depth_length < 1.0e4
        && length(cross(depth, w)) <= SQUARE_TOLERANCE * depth_length
}

/// A projection's screen row: a non-degenerate scaling of an axis perpendicular
/// to `forward`.
fn scaled_axis(row: [f32; 3], forward: [f32; 3]) -> bool {
    let length = length(row);
    (0.1..=1.0e4).contains(&length) && dot(row, forward).abs() <= SQUARE_TOLERANCE * length
}

fn transposed(m: &[f32; 16]) -> [f32; 16] {
    let mut out = [0f32; 16];
    for row in 0..4 {
        for column in 0..4 {
            out[row * 4 + column] = m[column * 4 + row];
        }
    }
    out
}

fn dot(a: [f32; 3], b: [f32; 3]) -> f32 {
    a[0] * b[0] + a[1] * b[1] + a[2] * b[2]
}

fn cross(a: [f32; 3], b: [f32; 3]) -> [f32; 3] {
    [
        a[1] * b[2] - a[2] * b[1],
        a[2] * b[0] - a[0] * b[2],
        a[0] * b[1] - a[1] * b[0],
    ]
}

fn length(v: [f32; 3]) -> f32 {
    dot(v, v).sqrt()
}

#[cfg(test)]
mod tests {
    use super::*;

    const BASE: u64 = 0x0000_7FF8_3000_0000;
    const DATA_RVA: u64 = 0x1000;
    const DATA_SIZE: u64 = 0x2000;

    fn image() -> Vec<u8> {
        vec![0u8; (DATA_RVA + DATA_SIZE) as usize]
    }

    fn ranges() -> Vec<(u64, u64)> {
        vec![(DATA_RVA, DATA_SIZE)]
    }

    fn place(image: &mut [u8], rva: u64, matrix: &[f32; 16]) {
        for (index, value) in matrix.iter().enumerate() {
            image[(rva + index as u64 * 4) as usize..][..4].copy_from_slice(&value.to_le_bytes());
        }
    }

    /// A world-to-clip matrix the way an engine builds one: a perspective
    /// projection applied to a camera basis, so the scan is tested against the
    /// geometry it claims to recognise rather than against numbers picked to
    /// pass.
    fn view_matrix(yaw: f32, pitch: f32, eye: [f32; 3], fov: f32, aspect: f32) -> [f32; 16] {
        let (yaw, pitch) = (yaw.to_radians(), pitch.to_radians());
        let forward = [
            pitch.cos() * yaw.cos(),
            pitch.cos() * yaw.sin(),
            -pitch.sin(),
        ];
        let right = [-yaw.sin(), yaw.cos(), 0.0];
        let up = cross(right, forward);

        let y_scale = 1.0 / (fov.to_radians() / 2.0).tan();
        let x_scale = y_scale / aspect;
        let (near, far) = (7.0f32, 4096.0f32);
        let (a, b) = (far / (far - near), -near * far / (far - near));

        // Rows of the view matrix, in the projection's own scaling.
        let row = |axis: [f32; 3], scale: f32| {
            [
                axis[0] * scale,
                axis[1] * scale,
                axis[2] * scale,
                -dot(axis, eye) * scale,
            ]
        };
        let screen_x = row(right, x_scale);
        let screen_y = row(up, y_scale);
        let depth = row(forward, a);
        let w = row(forward, 1.0);

        [
            screen_x[0],
            screen_x[1],
            screen_x[2],
            screen_x[3],
            screen_y[0],
            screen_y[1],
            screen_y[2],
            screen_y[3],
            depth[0],
            depth[1],
            depth[2],
            depth[3] + b,
            w[0],
            w[1],
            w[2],
            w[3],
        ]
    }

    fn sample() -> [f32; 16] {
        view_matrix(37.5, -12.0, [512.0, -1024.0, 64.0], 90.0, 16.0 / 9.0)
    }

    /// A rotation and a translation, which is what a module's data is actually
    /// full of: bones, attachments, entity transforms.
    fn affine_transform() -> [f32; 16] {
        let (yaw, pitch) = (0.7f32, -0.3f32);
        let forward = [
            pitch.cos() * yaw.cos(),
            pitch.cos() * yaw.sin(),
            -pitch.sin(),
        ];
        let right = [-yaw.sin(), yaw.cos(), 0.0];
        let up = cross(right, forward);
        [
            right[0], right[1], right[2], 128.0, //
            up[0], up[1], up[2], -64.0, //
            forward[0], forward[1], forward[2], 32.0, //
            0.0, 0.0, 0.0, 1.0,
        ]
    }

    #[test]
    fn finds_the_view_matrix_by_its_geometry() {
        let mut image = image();
        place(&mut image, DATA_RVA + 0x400, &sample());

        assert_eq!(
            find_in_image(&image, BASE, &ranges()),
            Some(BASE + DATA_RVA + 0x400)
        );
    }

    /// The layout convention is the engine's, and the address is the same under
    /// either, so a transposed matrix must be found too.
    #[test]
    fn a_column_major_matrix_is_found_too() {
        let mut image = image();
        place(&mut image, DATA_RVA + 0x800, &transposed(&sample()));

        assert_eq!(
            find_in_image(&image, BASE, &ranges()),
            Some(BASE + DATA_RVA + 0x800)
        );
    }

    /// The invariant that carries the whole scan: an affine transform's last row
    /// has no direction, so no amount of it in a module's data can be mistaken
    /// for a projection.
    #[test]
    fn affine_transforms_are_never_mistaken_for_a_projection() {
        let transform = affine_transform();
        assert!(!is_projection(&transform));
        assert!(!is_projection(&transposed(&transform)));

        let mut image = image();
        for slot in 0..8u64 {
            place(&mut image, DATA_RVA + 0x100 + slot * 0x40, &transform);
        }
        assert_eq!(find_in_image(&image, BASE, &ranges()), None);
    }

    /// Two matrices that both fit: one of them is a copy, and from inside a
    /// single image copy there is nothing to say which one the renderer keeps
    /// current. A stale view matrix draws a coherent, wrong world.
    #[test]
    fn a_second_matching_matrix_declines() {
        let mut image = image();
        place(&mut image, DATA_RVA + 0x400, &sample());
        place(
            &mut image,
            DATA_RVA + 0xC00,
            &view_matrix(180.0, 5.0, [0.0, 0.0, 0.0], 74.0, 4.0 / 3.0),
        );

        assert_eq!(find_in_image(&image, BASE, &ranges()), None);
    }

    #[test]
    fn a_module_without_a_view_matrix_yields_nothing() {
        assert_eq!(find_in_image(&image(), BASE, &ranges()), None);
    }

    /// Pointers and integers are what most of the section holds, and they are not
    /// float data: rejecting non-finite and implausibly large values is what
    /// stops the geometry tests from being asked about garbage.
    #[test]
    fn pointer_shaped_data_is_not_float_data() {
        let mut image = image();
        for slot in 0..8u64 {
            let value = (BASE + 0x1234 + slot * 0x40).to_le_bytes();
            image[(DATA_RVA + 0x200 + slot * 8) as usize..][..8].copy_from_slice(&value);
        }

        assert_eq!(find_in_image(&image, BASE, &ranges()), None);
        assert_eq!(floats(&[0xFFu8; 64]), None, "NaN is not a matrix element");
    }
}
