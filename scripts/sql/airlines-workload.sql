SELECT t.passenger_name,
       count(*) AS segment_count,
       max(f.scheduled_departure) AS latest_departure,
       count(bp.boarding_no) AS boarded
  FROM bookings.tickets t
  JOIN bookings.segments s ON s.ticket_no = t.ticket_no
  JOIN bookings.flights f ON f.flight_id = s.flight_id
  LEFT JOIN bookings.boarding_passes bp
    ON bp.ticket_no = s.ticket_no AND bp.flight_id = s.flight_id
 WHERE lower(t.passenger_name) = (
       SELECT lower(passenger_name)
         FROM bookings.tickets
        ORDER BY ticket_no
        LIMIT 1
 )
 GROUP BY t.passenger_name
 ORDER BY segment_count DESC;
