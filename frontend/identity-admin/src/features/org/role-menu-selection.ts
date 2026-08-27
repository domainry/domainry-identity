import type { MenuNode } from '@/data/types'

export interface RoleMenuTreeNode extends MenuNode {
  children: RoleMenuTreeNode[]
}

export function buildRoleMenuTree(menus: MenuNode[]): RoleMenuTreeNode[] {
  const byID = new Map<string, RoleMenuTreeNode>()
  for (const menu of menus) byID.set(menu.id, { ...menu, children: [] })

  const roots: RoleMenuTreeNode[] = []
  for (const menu of byID.values()) {
    const parent = menu.parentId ? byID.get(menu.parentId) : undefined
    if (parent && parent.id !== menu.id) parent.children.push(menu)
    else roots.push(menu)
  }

  const sort = (nodes: RoleMenuTreeNode[]) => {
    nodes.sort((left, right) => left.sort - right.sort || left.code.localeCompare(right.code))
    for (const node of nodes) sort(node.children)
  }
  sort(roots)
  return roots
}

function descendants(menuID: string, childrenByParent: Map<string, string[]>): string[] {
  const result: string[] = []
  const visit = (id: string) => {
    for (const childID of childrenByParent.get(id) ?? []) {
      result.push(childID)
      visit(childID)
    }
  }
  visit(menuID)
  return result
}

export function toggleRoleMenuSelection(
  menus: MenuNode[],
  selectedIDs: Iterable<string>,
  menuID: string,
  checked: boolean,
): string[] {
  const selected = new Set(selectedIDs)
  const byID = new Map(menus.map((menu) => [menu.id, menu]))
  const childrenByParent = new Map<string, string[]>()
  for (const menu of menus) {
    if (!menu.parentId) continue
    childrenByParent.set(menu.parentId, [...(childrenByParent.get(menu.parentId) ?? []), menu.id])
  }

  if (checked) {
    selected.add(menuID)
    for (const childID of descendants(menuID, childrenByParent)) selected.add(childID)
    let parentID = byID.get(menuID)?.parentId
    const visited = new Set<string>()
    while (parentID && !visited.has(parentID)) {
      visited.add(parentID)
      selected.add(parentID)
      parentID = byID.get(parentID)?.parentId
    }
  } else {
    selected.delete(menuID)
    for (const childID of descendants(menuID, childrenByParent)) selected.delete(childID)
  }

  return [...selected].filter((id) => byID.has(id)).sort()
}

export function roleMenuCheckState(node: RoleMenuTreeNode, selectedIDs: Set<string>): boolean | 'indeterminate' {
  const subtreeIDs: string[] = []
  const visit = (current: RoleMenuTreeNode) => {
    subtreeIDs.push(current.id)
    for (const child of current.children) visit(child)
  }
  visit(node)
  const selectedCount = subtreeIDs.filter((id) => selectedIDs.has(id)).length
  if (selectedCount === 0) return false
  if (selectedCount === subtreeIDs.length) return true
  return 'indeterminate'
}

export function filterRoleMenuTree(
  nodes: RoleMenuTreeNode[],
  query: string,
  label: (node: RoleMenuTreeNode) => string = (node) => node.name,
): RoleMenuTreeNode[] {
  const normalized = query.trim().toLocaleLowerCase()
  if (!normalized) return nodes
  return nodes.flatMap((node) => {
    const children = filterRoleMenuTree(node.children, normalized, label)
    const matches = [node.code, node.path, label(node)]
      .some((value) => value.toLocaleLowerCase().includes(normalized))
    return matches || children.length > 0 ? [{ ...node, children }] : []
  })
}
