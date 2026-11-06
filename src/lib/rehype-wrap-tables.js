/**
 * Wraps every Markdown <table> in a .table-wrapper so report tables
 * can scroll horizontally on small screens. Applies to all writeups
 * (TryHackMe, Hack The Box, CyberDefenders, and future reports).
 */
export function rehypeWrapTables() {
  return function transformer(tree) {
    wrapTables(tree);
  };
}

function classList(value) {
  if (Array.isArray(value)) return value;
  if (typeof value === 'string') return value.split(/\s+/).filter(Boolean);
  return [];
}

function wrapTables(node) {
  if (!node || !Array.isArray(node.children)) return;

  for (let i = 0; i < node.children.length; i++) {
    const child = node.children[i];
    wrapTables(child);

    if (child?.type !== 'element' || child.tagName !== 'table') continue;
    if (node.tagName === 'div' && classList(node.properties?.className).includes('table-wrapper')) {
      continue;
    }

    node.children[i] = {
      type: 'element',
      tagName: 'div',
      properties: { className: ['table-wrapper'] },
      children: [child],
    };
  }
}
