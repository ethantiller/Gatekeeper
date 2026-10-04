"use strict";

// Lays images out left to right and returns where each one goes on the sheet.
function pack(images) {
  let x = 0;
  const placements = images.map((image) => {
    const placement = { name: image.name, x, y: 0 };
    x += image.width;
    return placement;
  });
  return { width: x, height: Math.max(0, ...images.map((image) => image.height)), placements };
}

module.exports = { pack };
