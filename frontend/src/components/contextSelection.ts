export type ContextSelection = {all:boolean; selected:number[]; excluded:number[]}

export function selectPage(selection:ContextSelection, assetIds:number[]):ContextSelection {
  return {all:false, excluded:[], selected:[...new Set([...selection.selected,...assetIds])]}
}

export function toggleAsset(selection:ContextSelection, assetId:number, checked:boolean):ContextSelection {
  if(selection.all) return {...selection, excluded:checked
    ? selection.excluded.filter(id=>id!==assetId)
    : [...new Set([...selection.excluded,assetId])]}
  return {...selection, selected:checked
    ? [...new Set([...selection.selected,assetId])]
    : selection.selected.filter(id=>id!==assetId)}
}

export function selectionPayload(selection:ContextSelection, filters:Record<string,string>) {
  return selection.all
    ? {selection:filters, exclude_asset_ids:selection.excluded}
    : {asset_ids:selection.selected}
}
