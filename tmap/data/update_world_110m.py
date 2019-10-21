import re, json


def get_country_names():
	with open("./world-country-names.tsv", "r") as f:
		lines = f.readlines()

	id2name = dict()
	for line in lines:
		line = line.strip()
		tmp = line.split("\t")
		id2name[tmp[0]] = tmp[1]

	return id2name


def get_world_map():
	with open("world-110m.json", "r") as f:
		content = f.read()

	return json.loads(content)

def update_world_map(world):
	with open("world-110m-with-names.json", "w") as f:
		f.write(json.dumps(world))


if __name__ == '__main__':
	id2name = get_country_names()
	world = get_world_map()

	taiwan_idx = '-'
	china_idx = '-'
	geometry_num = len(world['objects']['countries']['geometries'])
	for i in range(0, geometry_num - 1):
		country_id = world['objects']['countries']['geometries'][i]['id']
		country_id = str(country_id)
		
		country_name = ''
		if country_id in id2name:
			country_name = id2name[country_id]
		
		world['objects']['countries']['geometries'][i]['properties'] = {'name':country_name}

		if 'taiwan' in country_name.lower():
			print('taiwan id: %s' % country_id)
			taiwan_idx = i
		elif 'china' in country_name.lower():
			print('china id: %s' % country_id)
			china_idx = i

	# Taiwan is belong to China
	if taiwan_idx != '-' and china_idx != '-':
		taiwan_type = world['objects']['countries']['geometries'][taiwan_idx]['type']
		china_type = world['objects']['countries']['geometries'][china_idx]['type']
		taiwan_arcs = world['objects']['countries']['geometries'][taiwan_idx]['arcs']
		china_arcs = world['objects']['countries']['geometries'][china_idx]['arcs']

		if taiwan_type == 'Polygon' and china_type == 'Polygon':
			world['objects']['countries']['geometries'][china_idx]['arcs'] = [taiwan_arcs, china_arcs]
			world['objects']['countries']['geometries'][china_idx]['type'] = 'MultiPolygon'
		elif taiwan_type == 'Polygon' and china_type == 'MultiPolygon':
			world['objects']['countries']['geometries'][china_idx]['arcs'].insert(0, taiwan_arcs)
		elif taiwan_type == 'MultiPolygon' and china_type == 'Polygon':
			# impossible
			pass
		elif taiwan_type == 'MultiPolygon' and china_type == 'MultiPolygon':
			world['objects']['countries']['geometries'][china_idx]['arcs'].extend(taiwan_arcs)

		world['objects']['countries']['geometries'].pop(taiwan_idx)

	update_world_map(world)
