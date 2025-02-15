 import base64
 import random
 import string
 import time
 
 # === Моделирование космического спутника ===
 class Satellite:
     def __init__(self, satellite_id):
         self.satellite_id = satellite_id
 
     def collect_data(self):
         """Собирает данные с сенсоров спутника."""
         temperature = random.uniform(-150, 150)  # Температура в космосе (°C)
         radiation = random.uniform(0.1, 100.0)  # Уровень радиации (μSv/h)
         timestamp = time.time()
         return {
             "satellite_id": self.satellite_id,
             "temperature": round(temperature, 2),
             "radiation": round(radiation, 2),
             "timestamp": timestamp,
         }
 
     def encode_data(self, data):
         """Кодирует данные в формат Base64 с псевдошифрованием."""
         # Преобразуем данные в строку
         data_str = "|".join(f"{key}:{value}" for key, value in data.items())
         # Кодируем в Base64
         encoded_bytes = base64.b64encode(data_str.encode('utf-8'))
         # Добавляем псевдошифрование (перемешиваем символы)
         scrambled = ''.join(random.sample(encoded_bytes.decode('utf-8'), len(encoded_bytes)))
         return scrambled
 
     def send_data(self):
         """Собирает, кодирует и передает данные."""
         data = self.collect_data()
         encoded_data = self.encode_data(data)
         return encoded_data
 
 # === Центр управления на Земле ===
 class GroundControl:
     def __init__(self):
         self.received_data = []
 
     def decode_data(self, scrambled_data):
         """Декодирует и расшифровывает данные."""
         # Попробуем восстановить и декодировать Base64
         for permutation in self._generate_permutations(scrambled_data):
             try:
                 decoded_bytes = base64.b64decode(permutation.encode('utf-8'))
                 decoded_str = decoded_bytes.decode('utf-8')
                 data = self._parse_data(decoded_str)
                 return data
             except Exception:
                 continue
         raise ValueError("Не удалось декодировать данные.")
 
     def _generate_permutations(self, scrambled):
         """Генерирует возможные комбинации (имитация подбора)."""
         # В реальной задаче это перебор вариантов. Ограничимся небольшим примером.
         yield scrambled  # Пример упрощенной логики.
 
     def _parse_data(self, decoded_str):
         """Парсит строку в формате key:value."""
         data = {}
         for pair in decoded_str.split('|'):
             key, value = pair.split(':')
             if key in ["temperature", "radiation"]:
                 value = float(value)
             elif key == "timestamp":
                 value = float(value)
             data[key] = value
         return data
 
     def receive_data(self, scrambled_data):
         """Получает, декодирует и сохраняет данные."""
         try:
             decoded_data = self.decode_data(scrambled_data)
             self.received_data.append(decoded_data)
             print(f"Получены данные: {decoded_data}")
         except ValueError as e:
             print(f"Ошибка при декодировании данных: {e}")
 
 
 
 # === Основной код ===
 def main():
     # Инициализация спутника и центра управления
     satellite = Satellite("Sat-2024")
     ground_control = GroundControl()
 
     # Эмуляция передачи данных
     print("Передача данных начата...")
     for _ in range(5):
         encoded_data = satellite.send_data()
         print(f"Закодированные данные: {encoded_data}")
         ground_control.receive_data(encoded_data)
         time.sleep(1)  # Задержка между передачами
 
     print(f"Передача данных завершена.\n\n\n")
 
 if __name__ == "__main__":
     for i in range(0, 10):
         main()
 
 
 
 ================================================================
 
 Передача данных начата...
 Закодированные данные: 4sllSa5xXM0FzMh2kdchGlHzRCHFxzyfliTDl200vMb0WwbYCcHM0jNhoMSOlOI4Zdb2falcBXXcTDxZ3OXJ00RIRAlN0JXl6W4OUNd0NI4mh1jG
 Ошибка при декодировании данных: Не удалось декодировать данные.
 Закодированные данные: WHGXTYN2X4NjDd3Dy52YXcNO0=Yz8M0CROQ6XNs22OIZM1dMWyMd4RBldSF00iMlYWpNkuM0UOpbHcXD01mXNjlxlxkhRzaJFl3tlwYl2ZyEMufbR=DI
 Ошибка при декодировании данных: Не удалось декодировать данные.
 Закодированные данные: Tjfh0NXXjRlOG0lzNFkIXMdjH2FOIoNbMWl0UcMRbdjs02lLlfZJdVlZHOuhyGatXBJQDX2YcGEL10MxDgwQ03Wl0MC8EzjlZlxyhzvmcdj0
 Ошибка при декодировании данных: Не удалось декодировать данные.
 Закодированные данные: XllWCj4Wxh24dOjz00gIhz2DmEMQFMTcZNkpkGRDuMyFHfWu018IMNNomclR9BWOOX0xl0x5NMHFIfjaFbJDciaLjszLbd0ORNcU0jt0jaFldXlVk=yX
 Ошибка при декодировании данных: Не удалось декодировать данные.
 Закодированные данные: RXjkcml62DtWMXYNiOl3u10E0MlXTFMjXQaNzRZixp2O00DXwY8MlXYZW0uRblNlM2dNOc44jJylHIA0WsfFbI2NG4MUxk244yRCdXzjRydNBhpO
 Ошибка при декодировании данных: Не удалось декодировать данные.
 Передача данных завершена.
 
 
 Передача данных начата...
 Закодированные данные: QdaGllZsjY2dXHjwWH2XXDljOjTYFllDIlFkObcHRZjVcgJYIcx0dtcOxJNRCmyBlyf0N3dhoGNvM0LjfWzoxN1b5LpRzhFfL0lbMjzghM2X0=TG
 Ошибка при декодировании данных: Не удалось декодировать данные.
 Закодированные данные: iWxOlYWcDHl0XRaFtN0yXpBOjZhd3Mz=Cw0k8OINd2MG2X44Nx2Elb0b3jdE3NuNjIXDQMMNDzOcf1XH2zmky=Y2ZUXy0uYNlFWlOlNCRp0sEJRR6xRl
 Ошибка при декодировании данных: Не удалось декодировать данные.
 Закодированные данные: UXlcWMz0lhzZWaloOxk2Y2N30mjy34lbZRh4llIMBdIjhsxRhbylxX0cDTdvzcdF02J1NHGf63J2aAjOXbl0Y0cLjMCi=3MfR0MHFCGcXkTMXNOl
 Ошибка при декодировании данных: Не удалось декодировать данные.
 Закодированные данные: EzfjlRkRzZmb0YhYNIcHXWlDRyFcBdsW=FG0DXCloc4TlzfD000ldxxhDjMJFOjLOcIxYHj2cMbWWFaMzYa09NQ2tuLX8iFjNONujylmNpXaMVdw1Oxk
 Ошибка при декодировании данных: Не удалось декодировать данные.
 Закодированные данные: ONW2NmFlk=fzNZd9jQdzOBW00MtMcXVIOF8loH0lyMCDFJdkc0DFX1ajy0x0uRRjjXajOxcLWclaib0McjpsLhLJNlmwczbGYl=RT10fQHX02FWU
 Ошибка при декодировании данных: Не удалось декодировать данные.
 Передача данных завершена.
 
 
 Передача данных начата...
 Закодированные данные: WWxz0MMAHDIkb3l0M0RJNUxSXTMl3lfTcRLh0OdxMTJf0l0h4djDXHGbX6hkwOm0ZvlNollzah4jOsFYb30g2xjX2cCBC2c1cllORXaYjyGZFcdN
 Ошибка при декодировании данных: Не удалось декодировать данные.
 Закодированные данные: FJ2Ey2h0bMjWlIsTcjX0NdDMNXMwNWUjE6DTdpRmay3clOy5y240RuWbuMxkpRRXY=lGAN4d03NUHzDkCOFlzXOYYNNNI2Etl2OZxfX1lX8ZlB00
 Ошибка при декодировании данных: Не удалось декодировать данные.
 Закодированные данные: MsMM2XllxTbADXjGWF0x4Rc=ONaojvdlkCdbl0aLNJMIZyjZX6j2lXOYzcMhMXY3GdQxk4RyXMlHH1l0fbOOcyDky00J004hRllwWBjcmhFhTfS1
 Ошибка при декодировании данных: Не удалось декодировать данные.
 Закодированные данные: QjNjs0DhWMcumUybMN0HlX2RDNOklX1FxolXmycxfczlazydQCDzOF2zy0FOkTjZ8aMLDWiWyYa0ZNdcUuW5R2RJfNllbIGM=0FHAXdB9FVO0tpLjcOx
 Ошибка при декодировании данных: Не удалось декодировать данные.
 Закодированные данные: HN2XjjRDXOFNNRkMEYdlUNOcXJ3YhFZt0WaTDcI2B0XCjf5lu8NyM=mXIl1T4R0bEdlxlMRHSlg03XdIsuGyxzDEM2d6wZWpl=cMWpbT442MMzMOxO0Y
 Ошибка при декодировании данных: Не удалось декодировать данные.
 Передача данных завершена.
 
 
 Передача данных начата...
 Закодированные данные: TFXRf6NlXFw8HDpMME1bxUtDdNEmbuyuWBw20N1uaNUW0zTdNRX3OWTjIOMI20Mp0XTscEOkZy=ilNx0RZxxl4zdlljYMlC2YJch=3XNAGYRd202UMlX
 Ошибка при декодировании данных: Не удалось декодировать данные.
 Закодированные данные: iY0lMh50Nxcicxfm0Wld1dhTaXJSR44XhDRbsF4XW1zlFZaNjkG12y6o0C2lldfDIMllbAOAOH4HX0lBOMTzGNU5lN3TiI0JhjRZX3M50vcHNbcM
 Ошибка при декодировании данных: Не удалось декодировать данные.
 Закодированные данные: xl3Ipw13cN2OEDlh0TiNTmEuXWd41NUNjMOFXs2Fldbk4OMXRD0Y8=NzfC2XMn0xANyMHTRa6Zl30NN=pIYFR0BZbNX2Ycyl0ldt4N0lXcuRNGWiJTTW
 Ошибка при декодировании данных: Не удалось декодировать данные.
 Закодированные данные: JzWWzy4NRcHONfUBol=i9Xdjpax0ldFQUcxyhNOjXb0kDNjaMV=FQNlWlFXzLCl0mgbFyJ0TAcsZN00aDGRDUUujO22uMlFXMft0kdcIMmR1W8H5xzLD
 Ошибка при декодировании данных: Не удалось декодировать данные.
 Закодированные данные: fucl20NHl5IyDaZUNz0TWUoO15lCFOdEMNjQX0JTjiFFchkyzX9ajclURWmc0MGfWxFjNmldlWF8y3NxMudH2kDMNcb0bxRsRX0cVajOptBXMDDL2RL=
 Ошибка при декодировании данных: Не удалось декодировать данные.
 Передача данных завершена.
 
 
 Передача данных начата...
 Закодированные данные: DGU9yRFjlDWdWUgfRjoOl0FLZWL1XJlBkzcahdmXlXMNjkNHksQbTMHcFubFpNc053wlM0WOck=O02Dj0ajIEflO8cXajyxtNxV0Mz2FRjmyudCV
 Ошибка при декодировании данных: Не удалось декодировать данные.
 Закодированные данные: lOYRIxlxJLNjMlVMMdYFCMUjX1xcTFylBwtuXocXZsfVpNcb0MhWL0ammQ0OkakFHgWFdUzjXNUWa0bNiORd0jylu2WR3G9zjlDNxzHjfy2UDTFx8c0=
 Ошибка при декодировании данных: Не удалось декодировать данные.
 Закодированные данные: XEZ=HhIl4RGNOFzlBO3jTlDlRM620YIzlNN02XydIcx28UyXcAFmwdO0XX0jZb2ux0CWNEjNT0lMXRpIkpOMOXslYNWRdIDI2FN4TYaby=1t2WJ40Nfu
 Ошибка при декодировании данных: Не удалось декодировать данные.
 Закодированные данные: ZlRC1kW1j34GJXMMljObajMMBG3WRU3z26ATJalfsbXljRMh40lM0FYl00codHmyd2MFLcjvcXMyNDN2Hll0nYXShblzcI4XhxOA1ZfY0dOx4h1T
 Ошибка при декодировании данных: Не удалось декодировать данные.
 Закодированные данные: l4slNYhXXZ5xR2Wcj4xJQN4XNT1llxWfBYXCImaDMEFcpYIO02RFO6M4aMkpWRHbyRSxNRydXdl1z3Y3X1z6A0MDM0bClTO2w0c0Nly2hcw0bjXM
 Ошибка при декодировании данных: Не удалось декодировать данные.
 Передача данных завершена.
 
 
 Передача данных начата...
 Закодированные данные: fcLdGolvWlb5dca6Awhz1FhMC2YajTfDyhRJkOQXOMlGi0Y2XORX0NNlFhX3bMYl41dMxH2lc3MJlZjcsyC1HlDMMxyj30mW30RZYB0j0XIb4Tly
 Ошибка при декодировании данных: Не удалось декодировать данные.
 Закодированные данные: abd=ljJHNbRjlz4zvWXwNFmAGaSLl1Z4ihfcMdIXlRchN0l00HX0CNRWQG2jdx1clXb0h6hOXo0B5S1MfMjF3YlDxl2NkcEYkX2MyZJT3TOszOjl
 Ошибка при декодировании данных: Не удалось декодировать данные.
 Закодированные данные: llYT0DA05X48nxNiXdOF430OWHWdm6Ia0OOOsctClUGOlpTYDx2hlYbwuI2zFluR2bXMy22=NX5N3ZcyMUdkJZwTDkZ40XjB=ElMpNS01RIOfjRMRWXN
 Ошибка при декодировании данных: Не удалось декодировать данные.
 Закодированные данные: YHO004ElOjWFNdUXu40a13EON6zcizl0W2My=IY2NXOsbY22JlXMDXHlTpOXDIdD2T0GbMZFtVu0NXfyhZlwpRROxiR4dOR8clO=QxClgTk14WBmwMNI
 Ошибка при декодировании данных: Не удалось декодировать данные.
 Закодированные данные: O4wXNd0zC0oMllllxcXhvGWcsltGbRFcUONyEdyhIjfgLyhoZpVFHNzl=bFMxkjDCm1fN2HjBRzXG21ZWaNlfjYXjljjLD0Db0zJRNNIHzddJ4ck
 Ошибка при декодировании данных: Не удалось декодировать данные.
 Передача данных завершена.
 
 
 Передача данных начата...
 Закодированные данные: wT0lXMnA1jl1Xo2lh4OdJjRFyDhhxMIjx0LDbj4jFY2b1TbGfhNRdzXHC0cGcA00mdkaBvcixWNla4OclJC1sXYlNxlfZHW32ZNO6wMMXNlMMclR
 Ошибка при декодировании данных: Не удалось декодировать данные.
 Закодированные данные: XDmus0XwONR2pOd2i0MylZy1NCMYchJZNMIjtDnOxjW0Y4l8zbUl2lRcTddlDJluyFa1RH6OXz0by32YGl3WM5XcBx0MFXkMMIYEf4zDXW0UpRIN
 Ошибка при декодировании данных: Не удалось декодировать данные.
 Закодированные данные: hjaZz0ldMHNXFDyXllNNtbMk2lND9ljjzJsVEkaMEdxMGl8ymfIIzAc0cW44EumXR2OF3jF1NWCyHORd2ZoLOAUxFDcFjbDpaXLBzA0WcWf=R0u0
 Ошибка при декодировании данных: Не удалось декодировать данные.
 Закодированные данные: ybNE0cThzTMXcphX2kmdDMNdFbYnlOf4bFjRyEHY0xOxlNRc0MplBa4C2XO30ylxQOl6NRWlXwzXMw1ak2JIZWycxWAusjS0T1RYXNljRcX60zO4
 Ошибка при декодировании данных: Не удалось декодировать данные.
 Закодированные данные: YIaptTRYlydYcWRIRMXIlkykXuD60z2b0NFYTl8xF0jMu3l4MCWNEyd3OOpf2M0lwC1sGX4bh0iNdMMmHMJxyZJl3ODOXXW2UZcT0AO0RT2lDB1X
 Ошибка при декодировании данных: Не удалось декодировать данные.
 Передача данных завершена.
 
 
 Передача данных начата...
 Закодированные данные: pTd=3G1XBORHNAJzXbCDTiN08XNXgNlj0YsDxxXyOYhImF2aOzpEdwt6CAjdMlfNluu4k22cW0lY4X=ZWRXNTlbZIA0WNl53yFR5MRlU21N1MMOk0cR0
 Ошибка при декодировании данных: Не удалось декодировать данные.
 Закодированные данные: MfbFkMaJ14ZjaBjjFlDglXcoHH3NJc2jlRhZc0DccdX1zlWYIM0wMzylCb3jCWmd0XMi5kM2TGllh4Ghb6shNEyARzl0Tv0X1RlMf0L2cOONdXxx
 Ошибка при декодировании данных: Не удалось декодировать данные.
 Закодированные данные: fclXzdXlx2E4y=l0IOYbcaZR0xYTp0ElYjwyDBNNWONXsl013jTtNWI0pSDFdl34XJNcbRuN2F6ECEXRHM2OyORjMMmUuhxk83J5=XZldMw2TWNOGYj0
 Ошибка при декодировании данных: Не удалось декодировать данные.
 Закодированные данные: lNj4XTysH3WxtbuO2pcAXI1=E0zR0Ed0OXNmO2lzC4MA0jjdDXaybXCENjBRNfNFGNRN6kRzxTZWUF2cll0YZJhjpYlkX2ld1IYluNXMlw8TOW30OO=I
 Ошибка при декодировании данных: Не удалось декодировать данные.
 Закодированные данные: XFk2OjgFNW3JmdsmylbILaBC0clMNXZODafDdRNaxliNEOMNRxN=UD41WIWuz20QtWOY0lG3lXXTMcFy=dk201ZlXl0F9dwuM8TkjjMMu0Ec8HODjh0l
 Ошибка при декодировании данных: Не удалось декодировать данные.
 Передача данных завершена.
 
 
 Передача данных начата...
 Закодированные данные: yTDMjcYRM2xCmMkaIpd2M0sYyJl80G0ZEuXFXX2OR30zhTRNYEUfIdORXDMyFMWlXlcZzBUtld4O2l61dONclXM5XWlcUSWzTH30N4jNypbuxbxw
 Ошибка при декодировании данных: Не удалось декодировать данные.
 Закодированные данные: MOct0WjW10XuxDg10lNjRRUxs0FRCacalmHzENyNcVaFWNczLOb0XdMhWDF8f0ilJUFl9OkIuyXZlQokBz2bdjFclNzLfpgDmkXNz=DzH2xN4d0G1jMl
 Ошибка при декодировании данных: Не удалось декодировать данные.
 Закодированные данные: NWNYltEdDpYgETXjmzCu21IlsX0FRyjNXMXcCWJOlhOBG0Xk3j=6lZ00DfHcd=D0N2OUOORlMbuw2Nx3Xa4WUMF5TI2bpRMlld0YkM4RzlO3ZXy8MTIx
 Ошибка при декодировании данных: Не удалось декодировать данные.
 Закодированные данные: tycRZHLljhMoWiXFMxHx9JVBcL0TlyklDIDFDXF8FzOuNyWMOO22dlk0WDfMwNMfQxslzRDMjGu00mhIjpl0Xa5=d2Obab1zgFWRNCMANXcUjOcjadm0
 Ошибка при декодировании данных: Не удалось декодировать данные.
 Закодированные данные: j0NafljRMMdlAdFHl0ZhNMfbE0JI0xXhj0Ts0XajNMlOEi2mXUYGw4WcxzbkF2TvWTg6GH2DCoj4kLRcSl5hcMXx5l3lM1R2cNXJyydOZ1XBlhbl
 Ошибка при декодировании данных: Не удалось декодировать данные.
 Передача данных завершена.
 
 
 Передача данных начата...
 Закодированные данные: z0dDO2ZdyX0d2cC=HLbMxcGXhFmlhJAjMwQlfcMRTcOz4XR3YyWFcToM62fJvN0GlxRNOlkb0Z1cl0UjXjaMhIW45Cba10TMHljzXsNlHlBghTil
 Ошибка при декодировании данных: Не удалось декодировать данные.
 Закодированные данные: Xj3EZHahjIONk0M0bYNM2l0FfxGcUSzIMIJyh6l4Njd1ODlo2m1XaWJyRj4c3yvH0fSRMNbZGdlXgz4XRhlXcT0xOljTFlbA0s4ldWMlcyCzLnBh
 Ошибка при декодировании данных: Не удалось декодировать данные.
 Закодированные данные: cjl1y42OZGBxMMT5bcS12EMXdXfl0jRMlkgYMLhHOHX1WQcvNORj4ad3NoFIsDGFThlZymfl1Rl0x0h0W0OzXlgxAck2j6bbadhCJlXj3CXlNJ4D
 Ошибка при декодировании данных: Не удалось декодировать данные.
 Закодированные данные: RU4XZmXVzacOf2u=gR1ct8aydcybuxXlJoOkDLGIR0jFx0WByl0Nh0dxOFDWQaf0mWMUFgXksFZp2AkjlIMCHHjNjWzdb0l2NjN0MO9xODTMFDlLcTil
 Ошибка при декодировании данных: Не удалось декодировать данные.
 Закодированные данные: 0BgMl8FdjWXpEuJ=XcUkzNRfIdXXhHl=0b3mM4YZ26OXlyMFItIl2UMx1pNilwTYRdlzO4M2Is0cYDjWCE2NW1XGRdzw10NNayM04buzDlZj2TNxnORM
 Ошибка при декодировании данных: Не удалось декодировать данные.
 Передача данных завершена.
 
 
 
 
 