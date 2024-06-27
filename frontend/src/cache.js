export let routers;
export let tables;

async function get_routers() {
	const resp = await fetch("/api/routers")
	const json = await resp.json()

	return Object.entries(json).sort((a, b) => a[1].client_name > b[1].client_name)
}

export const initCache = async () => {
	routers = await get_routers();
	tables = await fetch("/api/routing-instances").then(resp => resp.json());
};
