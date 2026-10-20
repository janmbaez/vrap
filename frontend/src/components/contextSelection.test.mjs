import {test} from 'node:test'
import assert from 'node:assert/strict'
import {selectPage, toggleAsset, selectionPayload} from './contextSelection.ts'

test('select page deduplicates assets that have multiple findings', () => {
  const chosen = selectPage({all:false, selected:[], excluded:[]}, [11, 11, 12])
  assert.deepEqual(chosen.selected, [11, 12])
  assert.deepEqual(selectionPayload(chosen, {q:'unused'}), {asset_ids:[11,12]})
})

test('select all spans pages and exclusions persist through preview and confirmation', () => {
  let chosen = {all:true, selected:[], excluded:[]}
  chosen = toggleAsset(chosen, 22, false)
  const filters = {subcategory:'Windows Servers', regulatory:'PCI DSS'}
  const preview = selectionPayload(chosen, filters)
  const confirmation = selectionPayload(chosen, filters)
  assert.deepEqual(preview, {selection:filters,exclude_asset_ids:[22]})
  assert.deepEqual(confirmation, preview)
  chosen = toggleAsset(chosen, 22, true)
  assert.deepEqual(chosen.excluded, [])
})
