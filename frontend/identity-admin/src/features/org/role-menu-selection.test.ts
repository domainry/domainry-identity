import { describe, expect, it } from 'vitest'
import type { MenuNode } from '@/data/types'
import { buildRoleMenuTree, filterRoleMenuTree, roleMenuCheckState, toggleRoleMenuSelection } from './role-menu-selection'

const menus: MenuNode[] = [
  { id: 'hr', parentId: null, name: 'Human resources', code: 'hr', path: '', type: 'group', sort: 10, visible: true },
  { id: 'leave', parentId: 'hr', name: 'Leave', code: 'leave', path: '/hr/leave', type: 'page', sort: 20, visible: true },
  { id: 'drafts', parentId: 'leave', name: 'Drafts', code: 'drafts', path: '/hr/leave/drafts', type: 'page', sort: 30, visible: true },
  { id: 'system', parentId: null, name: 'System', code: 'system', path: '', type: 'group', sort: 40, visible: true },
]

describe('role menu selection', () => {
  it('adds ancestors and descendants so selected entries stay reachable', () => {
    expect(toggleRoleMenuSelection(menus, [], 'drafts', true)).toEqual(['drafts', 'hr', 'leave'])
    expect(toggleRoleMenuSelection(menus, [], 'hr', true)).toEqual(['drafts', 'hr', 'leave'])
  })

  it('removes a complete subtree when a parent is unchecked', () => {
    expect(toggleRoleMenuSelection(menus, ['drafts', 'hr', 'leave', 'system'], 'leave', false)).toEqual(['hr', 'system'])
  })

  it('reports partial parent selection and retains ancestors during search', () => {
    const tree = buildRoleMenuTree(menus)
    expect(roleMenuCheckState(tree[0], new Set(['hr', 'leave']))).toBe('indeterminate')
    expect(filterRoleMenuTree(tree, 'drafts')[0].children[0].children[0].id).toBe('drafts')
  })
})
