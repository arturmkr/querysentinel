SET work_mem = '64kB';

SELECT count(*)
FROM (
    SELECT parts.part_num
    FROM lego_inventory_parts AS parts
    ORDER BY md5(parts.part_num || parts.inventory_id::text)
) AS sorted_parts;
